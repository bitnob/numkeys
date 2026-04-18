#!/bin/bash
# Install script for NumKeys CLI

set -e

echo "🚀 Installing NumKeys..."

# Get the directory where the script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$( cd "$SCRIPT_DIR/.." && pwd )"

# Build release if not already built
if [ ! -f "$PROJECT_ROOT/target/release/numkeys" ]; then
    echo "📦 Building release binary..."
    cd "$PROJECT_ROOT"
    cargo build --release --bin numkeys
fi

# Get the full path to the binary
NUMKEYS_PATH="$PROJECT_ROOT/target/release/numkeys"

# Detect shell
if [ -n "$ZSH_VERSION" ]; then
    SHELL_RC="$HOME/.zshrc"
    SHELL_NAME="zsh"
elif [ -n "$BASH_VERSION" ]; then
    SHELL_RC="$HOME/.bashrc"
    SHELL_NAME="bash"
else
    SHELL_RC="$HOME/.profile"
    SHELL_NAME="sh"
fi

# Create alias
ALIAS_LINE="alias numkeys='$NUMKEYS_PATH'"

# Check if alias already exists
if grep -q "alias numkeys=" "$SHELL_RC" 2>/dev/null; then
    echo "⚠️  Updating existing numkeys alias..."
    # Remove old alias
    sed -i.bak '/alias numkeys=/d' "$SHELL_RC"
fi

# Add new alias
echo "" >> "$SHELL_RC"
echo "# NumKeys CLI" >> "$SHELL_RC"
echo "$ALIAS_LINE" >> "$SHELL_RC"

echo "✅ NumKeys installed successfully!"
echo ""
echo "📍 Binary location: $NUMKEYS_PATH"
echo "📝 Alias added to: $SHELL_RC"
echo ""
echo "🔄 To use numkeys immediately, run:"
echo "   source $SHELL_RC"
echo ""
echo "Or start a new terminal session."
echo ""
echo "📚 Usage examples:"
echo "   numkeys setup    # Setup a new issuer"
echo "   numkeys start    # Start the issuer node"
echo "   numkeys stop     # Stop the issuer node"
echo "   numkeys --help   # Show all commands"