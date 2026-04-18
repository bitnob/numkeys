//! Setup command for initializing a new issuer.

use crate::output;
use clap::Args;
use dialoguer::{theme::ColorfulTheme, Confirm, Input};
use numkeys_core::IssuerSetupBuilder;
use std::path::PathBuf;

/// Setup a new NumKeys issuer with interactive configuration.
#[derive(Debug, Args)]
pub struct SetupIssuerCmd {
    /// Output directory for configuration and keys.
    /// If not specified, defaults to ~/.numkeys/issuer/<name>
    #[arg(short, long)]
    output_dir: Option<PathBuf>,

    /// Name for this issuer configuration (used for directory naming).
    /// Defaults to 'default'
    #[arg(short, long, default_value = "default")]
    name: String,

    /// Skip interactive prompts and use defaults.
    #[arg(long)]
    non_interactive: bool,
}

impl SetupIssuerCmd {
    pub fn execute(self) -> anyhow::Result<()> {
        // Fun ASCII art banner
        println!("\n{}", "═".repeat(60));
        println!(
            r#"
    ╦ ╦┌─┐┌─┐┬ ┬┌─┐  ╔╗╔┌─┐┌┬┐┌─┐
    ╠═╣├┤ └─┐├─┤├─┤  ║║║│ │ ││├┤ 
    ╩ ╩└─┘└─┘┴ ┴┴ ┴  ╝╚╝└─┘─┴┘└─┘
    
    🚀 Let's set up your node! 🚀
        "#
        );
        println!("{}\n", "═".repeat(60));

        output::info("Welcome to NumKeys Protocol Setup");
        println!("Setting up your issuer node for the first time.\n");

        // Determine output directory
        let output_dir = self.output_dir.unwrap_or_else(|| {
            let home = dirs::home_dir().expect("Could not find home directory");
            home.join(".numkeys").join("issuer").join(&self.name)
        });

        // Show where we're saving
        println!("Configuration will be saved to: {}\n", output_dir.display());

        let theme = ColorfulTheme::default();

        // Collect configuration interactively
        let name = if self.non_interactive {
            "Test Issuer".to_string()
        } else {
            Input::with_theme(&theme)
                .with_prompt("Enter your issuer name (e.g., 'Acme Verification Services')")
                .validate_with(|input: &String| {
                    if input.trim().is_empty() {
                        Err("Issuer name cannot be empty")
                    } else {
                        Ok(())
                    }
                })
                .interact_text()?
        };

        let issuer_domain = if self.non_interactive {
            "issuer.example.com".to_string()
        } else {
            println!("\nYour issuer domain is where verifiers will find your public key.");
            println!("This MUST be a domain you control and can serve HTTPS content from.");
            Input::with_theme(&theme)
                .with_prompt("Enter your issuer domain (e.g., 'issuer.example.com')")
                .validate_with(|input: &String| {
                    if input.contains("://") {
                        Err("Please enter domain only, without protocol")
                    } else if input == "localhost" || input.starts_with("localhost:") {
                        Ok(()) // Allow localhost for development
                    } else if !input.contains('.') {
                        Err("Invalid domain format")
                    } else {
                        Ok(())
                    }
                })
                .interact_text()?
        };

        let contact_email = if self.non_interactive {
            "admin@example.com".to_string()
        } else {
            Input::with_theme(&theme)
                .with_prompt("Enter contact email for this issuer")
                .validate_with(|input: &String| {
                    if !input.contains('@') {
                        Err("Invalid email format")
                    } else {
                        Ok(())
                    }
                })
                .interact_text()?
        };

        // Build the configuration
        println!("\n{}", "─".repeat(60));
        println!("🔑 Generating Ed25519 keypair for signing attestations...");
        println!("{}", "─".repeat(60));

        let setup = IssuerSetupBuilder::new()
            .name(&name)
            .domain(&issuer_domain)
            .contact_email(&contact_email)
            .build()?;

        // Review configuration
        if !self.non_interactive {
            println!("\n📋 Review Configuration");
            println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            println!("Issuer Name: {}", setup.config.identity.name);
            println!("Issuer Domain: {}", setup.config.identity.domain);
            println!("Public Key URL: {}", setup.public_key_url());
            println!("Contact Email: {}", setup.config.identity.contact_email);
            println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

            let confirm = Confirm::with_theme(&theme)
                .with_prompt("Is this configuration correct?")
                .interact()?;

            if !confirm {
                println!("Setup cancelled.");
                return Ok(());
            }
        }

        // Save configuration
        output::info("Saving configuration and keys...");
        setup.save(&output_dir)?;

        output::success(&format!(
            "✅ Configuration saved to {}/config/issuer.toml",
            output_dir.display()
        ));
        output::success(&format!("✅ Keys saved to {}/keys/", output_dir.display()));

        // Display public key for easy copying
        println!("\n{}", "─".repeat(60));
        println!("📋 Your Public Key (copy this!):");
        println!("{}", "─".repeat(60));
        println!("\n{}\n", setup.config.identity.public_key_base64url);
        println!("{}", "─".repeat(60));

        // Show critical backup information with ASCII art
        println!("\n{}", "═".repeat(60));
        println!(
            r#"
    ⚠️  🔐 CRITICAL: BACKUP YOUR PRIVATE KEY! 🔐 ⚠️
    
    ┌─────────────────────────────────────────┐
    │   Your private key is stored at:       │
    │   {}/keys/private.key                   │
    └─────────────────────────────────────────┘
        "#,
            output_dir.display()
        );
        println!("{}", "═".repeat(60));

        println!("\n📋 Backup Checklist:");
        println!("  □ Copy private key to encrypted storage");
        println!("  □ Store backups in multiple locations");
        println!("  □ Never commit to version control");
        println!("  □ Consider hardware security module (HSM)");

        // Success message with celebration
        println!("\n{}", "─".repeat(60));
        println!(
            r#"
    ✨ 🎉 Setup Complete! 🎉 ✨
    
    Your issuer identity has been created!
        "#
        );
        println!("{}", "─".repeat(60));

        // Next steps with nice formatting
        println!("\n🚀 Next Steps:\n");

        println!("1️⃣  Deploy your public key:");
        println!(
            "    📍 URL: https://{}/.well-known/numkeys/pubkey.json",
            setup.config.identity.domain
        );
        println!(
            "    📄 File: {}/config/public-key-endpoint.json\n",
            output_dir.display()
        );

        println!("2️⃣  Configure DNS:");
        println!(
            "    🌐 Point {} → your server IP\n",
            setup.config.identity.domain
        );

        println!("3️⃣  Start your issuer node:");
        println!(
            "    💻 NUMKEYS_CONFIG_DIR={} cargo run --bin issuer-node",
            output_dir.display()
        );
        println!(
            "    Or: CONFIG_PATH={}/config/issuer.toml cargo run --bin issuer-node\n",
            output_dir.display()
        );

        println!("4️⃣  Test everything:");
        println!("    🧪 numkeys verify --help\n");

        println!("{}", "═".repeat(60));
        println!("Happy issuing! 🚀");
        println!("{}\n", "═".repeat(60));

        Ok(())
    }
}
