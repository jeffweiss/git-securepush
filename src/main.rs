#[macro_use] extern crate lazy_static;
extern crate git2;
extern crate gpgme;
extern crate crypto;
extern crate regex;

use git2::{Error, Oid, Repository};
use std::process::{Command, ExitStatus, Stdio};
use std::fs::File;
use std::io::{Read, Write};
use crypto::digest::Digest;
use crypto::sha1::Sha1;
use regex::Regex;

const RSL_BRANCH_NAME: &'static str = "rsl";

#[derive(Debug)]
struct RSLPushEntry {
    related_commits: Vec<Oid>,
    branch: String,
    head: Oid,
    prev_hash: Option<Oid>,
}

impl std::fmt::Display for RSLPushEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let prev_hash = match self.prev_hash {
            Some(oid) => format!("{}", oid),
            None => String::from(""),
        };

        let commits : Vec<String> = self.related_commits.iter().map(|o| format!("{}", o)).collect::<Vec<String>>();
        let related_commits : &[String] = &commits;
        let stringified_commits = related_commits.join(" ");
        write!(f, "Related Commits\n{related_commits}\nBranch:{branch}\nHEAD:{head}\nPREV_HASH:{prev_hash}",
               related_commits=stringified_commits,
               branch=self.branch,
               head=self.head,
               prev_hash=prev_hash)
    }
}

fn update_rsl_push(repo: &Repository) -> RSLPushEntry {
    println!("Updating the RSL");
    let push_entry = create_push_entry(repo);

    //TODO change to use libgit2
    let checkout_process = Command::new("git")
        .arg("-C")
        .arg(repo.workdir().unwrap())
        .arg("checkout")
        .arg("-q")
        .arg(RSL_BRANCH_NAME)
        .status()
        .unwrap();
    assert!(checkout_process.success());

    push_entry
}

fn create_push_entry(repo: &Repository) -> RSLPushEntry {
    let head = repo.head().unwrap();
    let target = head.target().unwrap();
    let mut revwalk = repo.revwalk().unwrap();
    assert!(revwalk.push(target).is_ok());
    let hashs: Vec<Oid> = revwalk.map(|o| o.unwrap()).collect();

    let current_branch_name = current_branch_name(repo);
    RSLPushEntry {
        related_commits: hashs,
        branch: current_branch_name.clone(),
        head: target,
        prev_hash: None
    }
}

fn rsl_init(repo: &Repository) -> RSLPushEntry {
    println!("Initializing the RSL");
    let push_entry = create_push_entry(repo);

    //TODO: Change from command to calling libgit2
    let checkout = Command::new("git")
        .arg("-C")
        .arg(repo.workdir().unwrap())
        .arg("checkout")
        .arg("-q")
        .arg("--orphan")
        .arg(RSL_BRANCH_NAME)
        .status()
        .unwrap();
    assert!(checkout.success());

    //TODO: Change from command to calling libgit2
    let clean = Command::new("git")
        .arg("-C")
        .arg(repo.workdir().unwrap())
        .arg("rm")
        .arg("-qrf")
        .arg(repo.workdir().unwrap())
        .status()
        .unwrap();
    assert!(clean.success());

    push_entry
}

fn rsl_fetch(repo: &Repository) -> Option<usize> {
    let fetch_process = Command::new("git")
        .arg("-C")
        .arg(repo.workdir().unwrap())
        .arg("fetch")
        .arg("-q")
        .arg("origin")
        .arg(RSL_BRANCH_NAME)
        .status()
        .unwrap();
    assert!(fetch_process.success());

    let checkout_process = Command::new("git")
        .arg("-C")
        .arg(repo.workdir().unwrap())
        .arg("checkout")
        .arg("-q")
        .arg(RSL_BRANCH_NAME)
        .status()
        .unwrap();
    assert!(checkout_process.success());

    let last_verified_push_entry = find_most_recent_push_entry(repo);

    let merge_process = Command::new("git")
        .arg("-C")
        .arg(repo.workdir().unwrap())
        .arg("checkout")
        .arg("-q")
        .arg(RSL_BRANCH_NAME)
        .status()
        .unwrap();
    assert!(merge_process.success());


    last_verified_push_entry
}

// fn create_initial_commit(repo: &Repository) -> Result<(), Error> {
//     let sig = try!(repo.signature());
//
//     let tree_id = {
//         let mut index = try!(repo.index());
//
//         try!(index.write_tree())
//     };
//
//     let tree = try!(repo.find_tree(tree_id));
//
//     try!(repo.commit(Some("HEAD"), &sig, &sig, "Initial commit", &tree, &[]));
//
//     Ok(())
// }

fn sign_rsl(repo: &Repository, push_entry: RSLPushEntry) -> Result<(), Error> {
    let count = count_files(repo);
    let filename = count + 1;
    let filepath = repo.workdir().unwrap().join(format!("{}", filename));
    // println!("We have {:?}", count);

    //TODO: Change from executing command to calling libgpgme
    let mut signing_process = Command::new("gpg2")
        .arg("--clearsign")
        .arg("-q")
        .arg("-o")
        .arg(&filepath)
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();

    {
        let stdin = signing_process.stdin.as_mut().unwrap();
        assert!(stdin.write_all(format!("{}", push_entry).as_bytes()).is_ok());
    }

    println!("clear signing RSL push entry");
    assert!(signing_process.wait_with_output().unwrap().status.success());

    println!("committing RSL push entry");
    //
    // TODO: figure out how to make this sign the RSL commit too
    // let sig = repo.signature().unwrap();
    //
    // let tree_id = {
    //     let mut index = try!(repo.index());
    //
    //     let filepath = format!("{}", filename);
    //     let path = Path::new(&filepath);
    //     println!("attempting to add {:?}", path);
    //
    //     match index.add_path(path) {
    //         Ok(()) => println!("added file"),
    //         Err(err) => println!("could not add file: {}", err),
    //     };
    //     try!(index.write_tree())
    // };
    //
    // println!("Our tree id is {:?}", tree_id);
    //
    // let tree = try!(repo.find_tree(tree_id));
    //
    // println!("Our tree is {:?}", tree.id());
    //
    // //TODO: This always creates an orphan commit
    // let oid = match repo.commit(Some("HEAD"), &sig, &sig, "Add RSL push entry", &tree, &[]) {
    //     Ok(oid) => oid,
    //     Err(err) => panic!("error committing: {}", err),
    // };
    // println!("New commit is {}", oid);
    //
    //

    let add_process = Command::new("git")
        .arg("-C")
        .arg(repo.workdir().unwrap())
        .arg("add")
        .arg(filepath)
        .status()
        .unwrap();
    assert!(add_process.success());

    let commit_process = Command::new("git")
        .arg("-C")
        .arg(repo.workdir().unwrap())
        .arg("commit")
        .arg("-S")
        .arg("-q")
        .arg("-m")
        .arg("Add RSL push entry")
        .status()
        .unwrap();
    assert!(commit_process.success());
    Ok(())

}

fn count_files(repo: &Repository) -> usize {
    let files = std::fs::read_dir(repo.workdir().unwrap())
        .unwrap();
    let entries = files.filter_map(|f| f.ok())
        .filter_map(|f| f.metadata().ok())
        .filter(|f| f.is_file());
    entries.count()
}

// fn my_push_update_reference(reference: &str, status: Option<&str>) -> Result<(), git2::Error> {
//     println!("push_update callback:\n\treference: {}\n\tstatus: {:?}", reference, status);
//     match status {
//         None => Ok(()),
//         Some(err) => Err(git2::Error::from_str(err)),
//     }
// }

fn push_rsl(repo: &Repository) -> Result<ExitStatus, std::io::Error> {
    // TODO: figure out how to make this work using default authentication
    // let fn_callback = &my_push_update_reference;
    // let mut push_options = git2::PushOptions::new();
    // let mut remote_callbacks = git2::RemoteCallbacks::new();
    // remote_callbacks.push_update_reference(fn_callback);
    // push_options.remote_callbacks(remote_callbacks);
    //
    // let mut origin = repo.find_remote("origin").unwrap();
    // let options = Some(&mut push_options);
    // match origin.push(&[RSL_BRANCH_NAME], options) {
    //     Ok(ok) => println!("pushed {} branch", RSL_BRANCH_NAME),
    //     Err(err) => panic!("Unable to push {} branch: {}", RSL_BRANCH_NAME, err),
    // };
    Command::new("git")
        .arg("-C")
        .arg(repo.workdir().unwrap())
        .arg("push")
        .arg("-q")
        .arg("origin")
        .arg(RSL_BRANCH_NAME)
        .status()
}


fn push_branch(repo: &Repository, current_branch: &str) {
    //TODO change to use libgit2
    let checkout_process = Command::new("git")
        .arg("-C")
        .arg(repo.workdir().unwrap())
        .arg("checkout")
        .arg("-q")
        .arg(current_branch)
        .status()
        .unwrap();
    assert!(checkout_process.success());

    let push_process = Command::new("git")
        .arg("-C")
        .arg(repo.workdir().unwrap())
        .arg("push")
        .arg("-q")
        .arg("origin")
        .arg(current_branch)
        .status()
        .unwrap();
    assert!(push_process.success());
}

fn rsl_verify(repo: &Repository) {
    let checkout_process = Command::new("git")
        .arg("-C")
        .arg(repo.workdir().unwrap())
        .arg("checkout")
        .arg("-q")
        .arg(RSL_BRANCH_NAME)
        .status()
        .unwrap();
    assert!(checkout_process.success());


    let first_push_entry = find_first_push_entry(repo);
    let mut last_push_entry = find_most_recent_push_entry(repo);
    match last_push_entry {
        Some(file) => {
            if verify_push_entry_signature(repo, &file) {
                println!("Signature verification succeeded");
            } else {
                println!("Signature verification failed");
            }
        },
        None => println!("There is no prior RSL push entry. No need to verify signature"),
    };

    let mut verify = true;

    while verify {
        let upper_bound = match last_push_entry {
            Some(num) => num - 1,
            None => 0,
        };
        let second_to_last_push_entry = find_most_recent_push_entry_with_explicit_upper_bound(repo, upper_bound);

        let starting_file_to_hash = match second_to_last_push_entry {
            Some(num) => num,
            None => 1,
        };
        let last_push_entry_expected_hash = calculate_hash_of_prior_entries(repo, starting_file_to_hash, upper_bound);
        let last_push_entry_actual_hash = read_prev_hash_from_file(repo, last_push_entry.unwrap());
        if last_push_entry_expected_hash == last_push_entry_actual_hash {
            println!("Hash verification successful");
        } else {
            println!("Hash verification failed");
            println!("  Expected hash: {}", last_push_entry_expected_hash);
            println!("    Actual hash: {}", last_push_entry_actual_hash);
            std::process::exit(2);
        }

        if last_push_entry == second_to_last_push_entry || last_push_entry == first_push_entry || last_push_entry == None {
            verify = false;
        }
        last_push_entry = second_to_last_push_entry;
    }
}
fn read_prev_hash_from_file(repo: &Repository, file: usize) -> String {
    lazy_static! {
        static ref PREV_HASH_REGEX: Regex = Regex::new(r"^PREV_HASH:([0-9a-f]{40})$").unwrap();
    }
    let filepath = repo.workdir().unwrap().join(format!("{}", file));
    let mut contents = String::new();
    File::open(filepath).unwrap().read_to_string(&mut contents);
    let hash = match PREV_HASH_REGEX.captures(&contents) {
        Some(cap) => cap.get(0).map_or("", |m| m.as_str()),
        None => "",
    };
    String::from(hash)
}


fn calculate_hash_of_prior_entries(repo: &Repository, start: usize, last: usize) -> String {
    //TODO change to a more secure hashing algo than sha1
    let mut buffer = Vec::new();
    let mut hasher = Sha1::new();

    for n in start..last {
        let filepath = repo.workdir().unwrap().join(format!("{}", n));

        File::open(filepath).unwrap().read_to_end(&mut buffer);
    }

    hasher.input(&buffer);
    let hex = hasher.result_str();
    hex
}

fn verify_push_entry_signature(repo: &Repository, file: &usize) -> bool {
    let filepath = repo.workdir().unwrap().join(format!("{}", file));
    let verify_process = Command::new("gpg2")
        .arg("--verify")
        .arg(filepath)
        .status()
        .unwrap();

    verify_process.success()
}

fn current_branch_name(repo: &Repository) -> String {
    String::from(repo.head().unwrap().shorthand().unwrap())
}

fn rsl_file_in_repo(repo: &Repository, file_entry: usize) -> bool {
    let current_path = repo.workdir().unwrap().join(format!("{}", file_entry));
    current_path.exists() && current_path.is_file()
}

fn file_is_push_entry(repo: &Repository, file: &String) -> bool {
    let current_path = repo.workdir().unwrap().join(&file);
    println!("Checking {:?}", current_path);
    //TODO replace process call to grep
    let grep_process = Command::new("grep")
        .arg("-q")
        .arg("-E")
        .arg("-e")
        .arg("^HEAD:[0-9a-f]{40}$")
        .arg(current_path)
        .status()
        .unwrap();
    grep_process.success()
}

fn find_first_push_entry_with_explicit_upper_bound(repo: &Repository, count: usize) -> Option<usize> {
    for n in 1..count {
        let stringified_file = format!("{}", n);
        if file_is_push_entry(repo, &stringified_file) {
            return Some(n);
        }
    }
    None
}

fn find_first_push_entry(repo: &Repository) -> Option<usize> {
    let count = count_files(repo);
    find_first_push_entry_with_explicit_upper_bound(repo, count)
}

fn find_most_recent_push_entry_with_explicit_upper_bound(repo: &Repository, count: usize) -> Option<usize> {

    let mut current_file = count;

    while current_file > 0 && rsl_file_in_repo(&repo, current_file) {
        let stringified_file = format!("{}", current_file);

        if file_is_push_entry(repo, &stringified_file) {
            return Some(current_file);
        }

        current_file -= 1;
    }

    None
}

fn find_most_recent_push_entry(repo: &Repository) -> Option<usize> {
    let count = count_files(repo);
    find_most_recent_push_entry_with_explicit_upper_bound(repo, count)
}

fn main() {
    let repo = match Repository::open("/tmp/git") {
        Ok(repo) => repo,
        Err(e) => panic!("failed to open: {}", e),
    };

    let head = match repo.head() {
        Ok(head) => head,
        Err(e) => panic!("failed to find HEAD ref: {}", e),
    };

    let current_branch_name = match head.shorthand() {
        Some(name) => name,
        None => "<DETACHED>",
    };

    println!("HEAD is {}", current_branch_name);

    if current_branch_name == RSL_BRANCH_NAME {
        std::process::exit(1);
    }

    let remote_branch_name = format!("origin/{}", RSL_BRANCH_NAME);

    let push_entry = match repo.find_branch(&remote_branch_name, git2::BranchType::Remote) {
        Ok(branch) => {
            println!("found branch: {:?}", branch.name());
            update_rsl_push(&repo)
        },
        Err(err) => {
            println!("Couldn't find branch because {}", err);
            rsl_init(&repo)
        },
    };

    sign_rsl(&repo, push_entry);
    while !push_rsl(&repo).unwrap().success() {
        println!("RSL push failed");
        println!("fetching the RSL from server...");

        let reset_process = Command::new("git")
            .arg("-C")
            .arg(repo.workdir().unwrap())
            .arg("reset")
            .arg("--hard")
            .arg(format!("origin/{}", RSL_BRANCH_NAME))
            .status()
            .unwrap();
        assert!(reset_process.success());

        rsl_fetch(&repo);
        rsl_verify(&repo);

        let last_push_entry = find_most_recent_push_entry(&repo);
        println!("Most recent push entry: {:?}", last_push_entry);
    }

    push_branch(&repo, current_branch_name);

    rsl_fetch(&repo);
    rsl_verify(&repo);
}

