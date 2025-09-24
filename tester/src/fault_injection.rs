//! Fault injector for the tester.
//!
//! Copyright (C) 2025  Ardalan Amiri Sani
//!
//! This program is free software: you can redistribute it and/or modify
//! it under the terms of the GNU General Public License as published by
//! the Free Software Foundation, either version 3 of the License, or
//! (at your option) any later version.
//!
//! This program is distributed in the hope that it will be useful,
//! but WITHOUT ANY WARRANTY; without even the implied warranty of
//! MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//! GNU General Public License for more details.
//!
//! You should have received a copy of the GNU General Public License
//! along with this program.  If not, see <https://www.gnu.org/licenses/>.

use std::fs;
use std::io;
use syn::{parse_file, visit_mut::VisitMut, Block, Expr, File, Stmt};

struct FaultInjector {
    tag_counter: usize,
    num_injected_faults: usize,
}

impl FaultInjector {
    fn inject_stmt(&mut self) -> Stmt {
        let tag = format!("fault_tag_{}", self.tag_counter);
        self.tag_counter += 1;
        syn::parse_quote! {
            inject_fault!(#tag);
        }
    }

    fn ends_control_flow(stmt: &Stmt) -> bool {
        match stmt {
            Stmt::Expr(expr, _) => matches!(
                expr,
                Expr::Return(_)
                    | Expr::Break(_)
                    | Expr::Continue(_)
                    | Expr::Try(_)
                    | Expr::Yield(_)
            ),
            _ => false,
        }
    }

    fn is_tail_expression(stmt: &Stmt, block: &syn::Block) -> bool {
        if let Stmt::Expr(_, None) = stmt {
            std::ptr::eq(stmt, block.stmts.last().unwrap_or(stmt))
        } else {
            false
        }
    }
}

impl VisitMut for FaultInjector {
    fn visit_block_mut(&mut self, block: &mut Block) {
        let mut new_stmts = Vec::new();
        for stmt in &block.stmts {
            new_stmts.push(stmt.clone());
            let is_tail = Self::is_tail_expression(stmt, block);
            let ends = Self::ends_control_flow(stmt);
            if !(is_tail || ends) {
                new_stmts.push(self.inject_stmt());
                self.num_injected_faults += 1;
            }
        }
        block.stmts = new_stmts;

        syn::visit_mut::visit_block_mut(self, block);
    }
}

fn insert_use_statement(mut code: String) -> String {
    let use_stmt = "use secluso_client_server_lib::inject_fault;";
    let mut insert_pos = 0;

    for line in code.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("//!") || trimmed.is_empty() {
            insert_pos += line.len() + 1;
        } else {
            break;
        }
    }

    code.insert_str(insert_pos, &format!("{}\n", use_stmt));
    code
}

pub fn inject_faults(file_path: &str) -> io::Result<usize> {
    let code = fs::read_to_string(file_path)?;
    let mut syntax: File =
        parse_file(&code).map_err(|e| io::Error::other(format!("Parse error: {e}")))?;

    let mut injector = FaultInjector {
        tag_counter: 0,
        num_injected_faults: 0,
    };

    injector.visit_file_mut(&mut syntax);

    let modified_code = prettyplease::unparse(&syntax);
    let modified_code_updated = insert_use_statement(modified_code);
    fs::write(file_path, &modified_code_updated)?;

    println!("Modified file written");
    println!("%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%");
    println!("{}", modified_code_updated);
    println!("%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%");
    Ok(injector.num_injected_faults)
}
