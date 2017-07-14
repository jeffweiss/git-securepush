extern crate git2;
extern crate gpgme;

use git2::Repository;

fn main() {
    let repo = match Repository::open(".") {
        Ok(repo) => repo,
        Err(e) => panic!("failed to open: {}", e),
    };

    let head = match repo.head() {
        Ok(head) => head,
        Err(e) => panic!("failed to find HEAD ref: {}", e),
    };
    let current_branch = match head.name() {
        Some(name) => name,
        None => "<DETACHED>",
    };
    println!("HEAD is {}", current_branch);
}
