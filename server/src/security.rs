use std::io;
use std::io::ErrorKind;
use std::path::Path;

pub(crate) fn check_path_sandboxed(base: &Path, target: &Path) -> io::Result<()> {
    let canonical_base = base.canonicalize()?;

    // Walk up the target path until we find an existing ancestor
    let mut current = target;

    while !current.exists() {
        current = current.parent().ok_or_else(|| {
            io::Error::new(ErrorKind::InvalidInput, "No valid parent for target path")
        })?;
    }

    let canonical_check = current.canonicalize()?;

    if !canonical_check.starts_with(&canonical_base) {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "Access outside allowed directory",
        ));
    }

    Ok(())
}
