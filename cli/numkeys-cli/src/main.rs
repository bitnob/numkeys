//! NumKeys Protocol CLI.

mod commands;
mod config;
mod output;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "numkeys")]
#[command(about = "NumKeys Protocol CLI - Manage proxy phone numbers and attestations")]
#[command(long_about = "
The NumKeys Protocol CLI allows you to:
- Generate cryptographic keypairs for attestations
- Request proxy phone numbers from issuers
- Verify attestations and challenge responses
- Inspect attestation details

For more information about the NumKeys Protocol, visit: https://github.com/bitnob/numkeys
")]
#[command(version)]
#[command(author)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Enable verbose output
    #[arg(short, long, global = true)]
    verbose: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new Ed25519 keypair for attestations
    #[command(
        long_about = "\nGenerate a new Ed25519 keypair for use with the NumKeys Protocol.\n\nThe private key is used to sign verification response payloads, while the public key\nis included in attestation requests.\n\nOutput formats:\n  json   - JSON object with base64url-encoded keys (default)\n  hex    - Hexadecimal encoding\n  base64 - Base64url encoding (no padding)\n\nExamples:\n  # Generate and save to file\n  numkeys keygen > keys.json\n  \n  # Generate in hex format\n  numkeys keygen -f hex\n  \n  # Set as environment variable\n  export NUMKEYS_PRIVATE_KEY=$(numkeys keygen -f base64 | grep 'Private' | cut -d' ' -f3)\n"
    )]
    Keygen {
        /// Output format (json, hex, base64)
        #[arg(short, long, default_value = "json", value_name = "FORMAT")]
        format: String,
    },

    /// Request attestation from an issuer
    #[command(long_about = "
Request a proxy phone number attestation from an issuer.

The issuer will verify your phone number ownership (method varies by issuer)
and provide a signed JWT attestation that binds a proxy number to your public key.

Examples:
  # Request US proxy number (+100...)
  numkeys attest -i https://issuer.example.com -p +1234567890 -s 1
  
  # Request UK proxy number (+4400...)  
  numkeys attest -i https://issuer.example.com -p +447700123456 -s 44
  
  # Save attestation to file
  numkeys attest -i https://issuer.example.com -p +1234567890 -o attestation.jwt
")]
    Attest {
        /// Issuer URL (e.g., https://issuer.example.com)
        #[arg(short, long, value_name = "URL")]
        issuer: String,

        /// Phone number to attest (E.164 format)
        #[arg(short, long, value_name = "PHONE")]
        phone: String,

        /// Scope - country calling code for proxy number (e.g., 1, 44, 234)
        #[arg(short, long, value_name = "CODE")]
        scope: String,

        /// Private key file (or use NUMKEYS_PRIVATE_KEY env)
        #[arg(short, long, value_name = "FILE")]
        key: Option<String>,

        /// Output file for attestation
        #[arg(short, long, value_name = "FILE")]
        output: Option<String>,
    },

    /// Verify an attestation's cryptographic validity
    #[command(long_about = "
Verify the cryptographic validity of a NumKeys attestation.

This command:
1. Checks the JWT signature against the issuer's public key
2. Validates attestation structure and claim consistency
3. Verifies the binding proof
4. Optionally checks if a phone number matches the attestation

Examples:
  # Verify attestation from file
  numkeys verify -a attestation.jwt
  
  # Verify and check phone number
  numkeys verify -a attestation.jwt -p +1234567890
  
  # Verify inline JWT
  numkeys verify -a eyJ0eXAiOiJKV1Q...
")]
    Verify {
        /// Attestation file or JWT string
        #[arg(short, long, value_name = "FILE_OR_JWT")]
        attestation: String,

        /// Expected phone number to verify (optional)
        #[arg(short, long, value_name = "PHONE")]
        phone: Option<String>,
    },

    /// Display attestation details without verification
    #[command(long_about = "
Display the contents of a NumKeys attestation without verification.

This command decodes and displays:
- Proxy number assigned
- Phone hash (privacy-preserved)
- Issuer domain
- User public key
- Expiration time
- Other attestation metadata

Note: This does NOT verify the attestation. Use 'numkeys verify' for validation.

Examples:
  # Inspect attestation from file
  numkeys inspect attestation.jwt
  
  # Inspect inline JWT
  numkeys inspect eyJ0eXAiOiJKV1Q...
")]
    Inspect {
        /// Attestation file or JWT string
        #[arg(value_name = "FILE_OR_JWT")]
        attestation: String,
    },

    /// Display information about the NumKeys Protocol
    #[command(long_about = "
Display information about the NumKeys Protocol, including:
- Protocol overview and purpose
- Key concepts (proxy numbers, attestations, verification)
- Common use cases
- Links to documentation
")]
    Info,

    /// Setup a new NumKeys issuer with interactive configuration
    #[command(name = "setup")]
    #[command(long_about = "
Initialize a new NumKeys issuer node with proper configuration.

This command will:
1. Collect issuer identity information (name, domain, contact)
2. Generate Ed25519 keypairs for signing attestations
3. Configure database and server settings
4. Create all necessary directories and files
5. Generate the public key endpoint JSON

The setup process emphasizes security:
- Private keys are saved with restricted permissions
- You'll be prompted to backup your private key
- Configuration is validated before saving

Examples:
  # Interactive setup (recommended)
  numkeys setup
  
  # Setup in specific directory
  numkeys setup -o /path/to/issuer
  
  # Non-interactive setup with defaults
  numkeys setup --non-interactive
")]
    Setup(commands::setup_issuer::SetupIssuerCmd),

    /// Start the NumKeys issuer node
    #[command(name = "start")]
    #[command(long_about = "
Start the NumKeys issuer node using a configuration created with 'numkeys setup'.

Examples:
  # Start with default configuration
  numkeys start
  
  # Start with named configuration
  numkeys start -n myissuer
  
  # Start in background (daemon mode)
  numkeys start --daemon
")]
    Start(commands::start::StartCmd),

    /// Stop the NumKeys issuer node
    #[command(name = "stop")]
    #[command(long_about = "
Stop a running NumKeys issuer node.

Examples:
  # Stop default issuer
  numkeys stop
  
  # Stop named issuer
  numkeys stop -n myissuer
")]
    Stop(commands::stop::StopCmd),
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Set up basic logging
    if cli.verbose {
        std::env::set_var("RUST_LOG", "debug");
    }

    match cli.command {
        Commands::Keygen { format } => {
            commands::keygen::execute(&format)?;
        }
        Commands::Attest {
            issuer,
            phone,
            scope,
            key,
            output,
        } => {
            commands::attest::execute(
                &issuer,
                &phone,
                &scope,
                key.as_deref(),
                output.as_deref(),
            )
            .await?;
        }
        Commands::Verify { attestation, phone } => {
            commands::verify::execute(&attestation, phone.as_deref()).await?;
        }
        Commands::Inspect { attestation } => {
            commands::inspect::execute(&attestation)?;
        }
        Commands::Info => {
            commands::info::execute()?;
        }
        Commands::Setup(cmd) => {
            cmd.execute()?;
        }
        Commands::Start(cmd) => {
            cmd.execute()?;
        }
        Commands::Stop(cmd) => {
            cmd.execute()?;
        }
    }

    Ok(())
}
