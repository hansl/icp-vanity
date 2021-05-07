use clap::Clap;
use ic_agent::Identity;

fn encode_pem_private_key(key: &[u8]) -> String {
    let pem = pem::Pem {
        tag: "PRIVATE KEY".to_owned(),
        contents: key.to_vec(),
    };
    pem::encode(&pem)
}

fn generate_principal_loop(pattern: &str, loose: bool) {
    let rng = ring::rand::SystemRandom::new();
    let regex = regex::Regex::new(pattern).unwrap();

    loop {
        let pkcs8_bytes = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let key_pair = ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).unwrap();
        let id = ic_agent::identity::BasicIdentity::from_key_pair(key_pair);
        let principal = if loose {
            id.sender().unwrap().to_text().replace('-', "")
        } else {
            id.sender().unwrap().to_text()
        };

        if regex.is_match(&principal) {
            println!("{}\n{}\n", principal, encode_pem_private_key(&*pkcs8_bytes.as_ref()));
        }
    }
}

#[derive(Clap)]
struct Opts {
    /// A regular expression patter to match the principal. This should include dashes that
    /// are part of the principal (e.g. if you want to match `abcdef` with any dashes anywhere
    /// you will need to pass in "[-a][-b][-c][-d][-e][-f]".
    /// You can use the `--loose` flag to remove this specific limitation.
    pattern: String,

    /// Whether or not to take the dashes into account. Default to false.
    #[clap(long)]
    loose: bool,

    /// The number of jobs in parallel. By default uses 1 job.
    #[clap(long("jobs"), short('j'), default_value = "1")]
    jobs: usize,
}

fn main() {
    let opts: Opts = Opts::parse();
    let loose = opts.loose;

    (0..(opts.jobs))
        .map(|_| {
            let pattern = opts.pattern.clone();
            std::thread::spawn(move || {
                generate_principal_loop(&pattern, loose);
            })
        })
        .collect::<Vec<_>>()
        .into_iter()
        .fold((), |_, handle| {
            handle.join().unwrap();
        });
}
