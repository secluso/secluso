//! SPDX-License-Identifier: GPL-3.0-or-later
use anyhow::{bail, Context};
use fatfs::{FileSystem, FsOptions};
use std::fs::{File, OpenOptions};
use std::io::{self, ErrorKind, Read, Seek, SeekFrom, Write};
use std::path::Path;

const PROVISION_PARTITION_INDEX: usize = 3;

// The partition layout reference specifically is meta-secluso-os/wic/sdcard-raspberrypi.wks in https://github.com/secluso/os
// The Yocto WKS syntax reference used by that file is https://docs.yoctoproject.org/ref-manual/kickstart.html.
// A WIC file is a raw disk image produced by Yocto tooling (so the first bytes of the file are laid out like the first bytes of the storage device that will eventually be flashed)
// The Yocto WIC tool reference is https://docs.yoctoproject.org/dev-manual/wic.html.
// In the Secluso OS image, sector zero contains an MBR partition table, each partition entry points at a byte range inside the same file, and partition 3 contains the FAT filesystem mounted as /provision during first boot that we use for provisioning in the deploy tool
// Reference for the MBR partition table byte layout reference used by this parser: https://wiki.osdev.org/Partition_Table
// This module edits the WIC as a disk image rather than unpacking it through a mount helper for optimal cross compatibility across Windows, macOS and Linux.
//
// +----------------------+----------------------+----------------------+----------------------+
// | sector 0             | partition 1          | partition 2          | partition 3          |
// | MBR bootstrap bytes  | boot                 | rootfs               | /provision           |
// | partition table      | boot filesystem      | Linux rootfs         | 16MB FAT filesystem  |
// | 0x55aa signature     |                      |                      | provisioning files   |
// +----------------------+----------------------+----------------------+----------------------+
//
// Once we find a FAT partition range, fatfs interprets only that subrange as a filesystem, and the PartitionBlockDevice adapter makes the subrange look like an independent disk to fatfs.
// fatfs reference used for FileSystem over a custom Read + Write + Seek device: https://docs.rs/fatfs/latest/fatfs/

#[derive(Debug, Clone)]
pub struct ConstructedFile {
    pub image_path: String,
    pub contents: Vec<u8>,
}

impl ConstructedFile {
    pub fn new(image_path: impl Into<String>, contents: impl Into<Vec<u8>>) -> Self {
        Self {
            image_path: image_path.into(),
            contents: contents.into(),
        }
    }
}

struct PartitionBlockDevice {
    file: File,
    offset: u64,
    len: u64,
    position: u64,
}

impl PartitionBlockDevice {
    // fatfs expects a block-device-like object whose offsets are relative to the start of the filesystem, but our actual storage is the entirety of the WIC file
    // thus this translates every relative FAT read, seek, and write into an absolute file operation at partition_offset + relative_position.
    // FAT code should never be allowed to read or write through the logical end of the selected partition into another partition or into unused disk-image space
    // https://doc.rust-lang.org/std/io/trait.Read.html, https://doc.rust-lang.org/std/io/trait.Write.html, https://doc.rust-lang.org/std/io/trait.Seek.html
    fn new(file: File, offset: u64, len: u64) -> Self {
        Self {
            file,
            offset,
            len,
            position: 0,
        }
    }

    fn remaining(&self) -> u64 {
        self.len.saturating_sub(self.position)
    }
}

impl Read for PartitionBlockDevice {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // The adapter clamps each read to the remaining partition length before touching the underlying file.
        // callers can treat EOF as the end of the partition
        let amount = self.remaining().min(buf.len() as u64) as usize;
        if amount == 0 {
            return Ok(0);
        }

        self.file
            .seek(SeekFrom::Start(self.offset + self.position))?;
        let bytes_read = self.file.read(&mut buf[..amount])?;
        self.position += bytes_read as u64;
        Ok(bytes_read)
    }
}

impl Seek for PartitionBlockDevice {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        // Evaluated in signed space first so negative seeks and seeks past the partition boundary are rejected
        // code writes secrets into the image and should never corrupt unrelated partitions.
        let next = match pos {
            SeekFrom::Start(pos) => pos as i128,
            SeekFrom::End(delta) => self.len as i128 + delta as i128,
            SeekFrom::Current(delta) => self.position as i128 + delta as i128,
        };

        if next < 0 || next > self.len as i128 {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "seek outside partition",
            ));
        }

        self.position = next as u64;
        Ok(self.position)
    }
}

impl Write for PartitionBlockDevice {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // Writes are also clamped to the partition, and a write that would start beyond the partition is treated as WriteZero.
        let amount = self.remaining().min(buf.len() as u64) as usize;
        if amount == 0 {
            return Err(io::Error::new(
                ErrorKind::WriteZero,
                "write outside partition",
            ));
        }

        self.file
            .seek(SeekFrom::Start(self.offset + self.position))?;
        let bytes_written = self.file.write(&buf[..amount])?;
        self.position += bytes_written as u64;
        Ok(bytes_written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

#[derive(Debug, Clone)]
pub struct MbrPartition {
    pub index: usize,
    pub partition_type: u8,
    pub start_lba: u32,
    pub size_sectors: u32,
}

impl MbrPartition {
    pub fn offset_bytes(&self) -> u64 {
        // MBR partition entries store the start as a logical block address, and classic disk images use 512-byte sectors for that address calculation.
        // FAT driver needs a byte offset. thus, every partition access goes through this conversion before we open the subregion.
        self.start_lba as u64 * 512
    }

    pub fn len_bytes(&self) -> u64 {
        // size in the MBR is also expressed in 512-byte sectors, multiplying by 512 gives the exact byte length of the partition slice
        self.size_sectors as u64 * 512
    }

    pub fn is_fat(&self) -> bool {
        // These partition type values cover the common FAT12, FAT16, and FAT32 MBR identifiers
        matches!(self.partition_type, 0x01 | 0x04 | 0x06 | 0x0b | 0x0c | 0x0e)
    }
}

fn read_u32_le(buf: &[u8]) -> u32 {
    u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]])
}

pub fn parse_mbr(path: impl AsRef<Path>) -> anyhow::Result<Vec<MbrPartition>> {
    let path = path.as_ref();
    let mut f = File::open(path).with_context(|| format!("failed to open {}", path.display()))?;

    // Sector zero of an MBR-partitioned WIC image contains bootstrap bytes followed by four 16-byte partition entries beginning at byte 446 and a required 0x55aa signature at bytes 510 and 511.
    // The 0x55aa signature and the 16-byte partition entry structure are described in the MBR partition table reference (https://wiki.osdev.org/Partition_Table)
    // We only need the partition table metadata, so reading the first 512 bytes is enough to locate partition 3 without interpreting the boot partition or root filesystem.
    let mut mbr = [0u8; 512];
    f.read_exact(&mut mbr)
        .with_context(|| format!("failed to read MBR from {}", path.display()))?;

    if mbr[510] != 0x55 || mbr[511] != 0xaa {
        bail!("Invalid MBR signature");
    }

    let mut parts = vec![];

    for i in 0..4 {
        // Each MBR entry is fixed-width and little-endian, with the partition type at byte 4, the starting LBA at bytes 8 through 11, and the sector count at bytes 12 through 15.
        let offset = 446 + i * 16;
        let entry = &mbr[offset..offset + 16];

        let partition_type = entry[4];
        let start_lba = read_u32_le(&entry[8..12]);
        let size = read_u32_le(&entry[12..16]);

        if start_lba != 0 && size != 0 {
            parts.push(MbrPartition {
                index: i + 1,
                partition_type,
                start_lba,
                size_sectors: size,
            });
        }
    }

    if parts.is_empty() {
        bail!("No valid MBR partitions found");
    }

    Ok(parts)
}

pub fn select_partition(
    partitions: &[MbrPartition],
    requested_partition: Option<usize>,
) -> anyhow::Result<&MbrPartition> {
    let index = requested_partition.unwrap_or(PROVISION_PARTITION_INDEX);
    let partition = partitions
        .iter()
        .find(|part| part.index == index)
        .with_context(|| format!("partition {index} was not found"))?;

    if !partition.is_fat() {
        bail!(
            "partition {} is type 0x{:02x}, not a FAT /provision partition",
            partition.index,
            partition.partition_type
        );
    }

    Ok(partition)
}

pub fn inject_files(
    image_path: impl AsRef<Path>,
    requested_partition: Option<usize>,
    files: impl IntoIterator<Item = ConstructedFile>,
) -> anyhow::Result<MbrPartition> {
    let image_path = image_path.as_ref();
    let files = files.into_iter().collect::<Vec<_>>();
    if files.is_empty() {
        bail!("at least one file is required");
    }

    // First locate the partition table, then select the FAT /provision partition, then write the requested files into that filesystem root through the partition-bounded adapter.
    let partitions = parse_mbr(image_path)?;
    let partition = select_partition(&partitions, requested_partition)?.clone();

    inject_files_into_partition(image_path, &partition, files)?;

    Ok(partition)
}

fn inject_files_into_partition(
    image_path: &Path,
    partition: &MbrPartition,
    files: Vec<ConstructedFile>,
) -> anyhow::Result<()> {
    // only bytes changed should be the FAT directory and data clusters needed to create the injected files.
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(image_path)
        .with_context(|| format!("failed to open {} for read/write", image_path.display()))?;

    let device = PartitionBlockDevice::new(file, partition.offset_bytes(), partition.len_bytes());
    let fs = FileSystem::new(device, FsOptions::new()).with_context(|| {
        format!(
            "partition {} is not a readable FAT filesystem",
            partition.index
        )
    })?;

    let root = fs.root_dir();

    for file in files {
        validate_image_path(&file.image_path)?;
        let mut output = root
            .create_file(&file.image_path)
            .with_context(|| format!("failed to create {}", file.image_path))?;
        output
            .write_all(&file.contents)
            .with_context(|| format!("failed to write {}", file.image_path))?;
    }

    Ok(())
}

fn validate_image_path(path: &str) -> anyhow::Result<()> {
    // defense-in-depth boundary around the injected file names
    // https://doc.rust-lang.org/std/path/enum.Component.html
    let path = Path::new(path);
    if path.is_absolute() {
        bail!("image file path must be relative");
    }

    if path
        .components()
        .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        bail!("image file path must not contain '..'");
    }

    Ok(())
}
