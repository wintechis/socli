# socli - Solid Client CLI

A command-line interface for interacting with Community Solid Server (CSS), providing basic authentication, data management, and RDF operations.

## Features

- User management with OIDC authentication
- DPoP (Demonstration of Proof-of-Possession) token handling
- Fetch and upload content to Solid pods
- Type index management (public/private)
- RDF/ACL permission management
- Notification subscriptions
- Interactive inbox management

## Requirements

- Python >=3.13
- Community Solid Server with Mashlib (required for type index operations)
  - Mashlib automatically creates profile and settings containers with public/private type indexes
  - Without Mashlib, type index operations may fail

## Installation

### Option 1: Development (currently preferred)

```bash
# Clone repository
git clone <repository-url>
cd socli

# recommended for development
uv sync
# activate venv (watch out for your shell!)
. .venv/bin/activate.fish

# Run in development mode
socli --help
```

### Option 2: Build and Install Locally (preliminary)

```bash
# Clone repository
git clone <repository-url>
cd socli

# Build and install the package
uv build
pip install dist/socli-*.whl

# Now you can use socli directly
socli --help
```

## Usage

The CLI is accessed through `uv run socli` or `socli` followed by a command and options.

### User Management

#### Add a New User

```bash
socli add \
  --role myuser \
  --email user@example.com \
  --password <password> \
  --webid https://solidserver.com/user/profile/card#me \
  --oidc https://solidserver.com \
  --database ./.db.toml
```

Options:

- `-r, --role`: Unique identifier for the user
- `-e, --email`: User's email address
- `-p, --password`: User's password (hidden input)
- `-w, --webid`: User's WebID URL
- `-o, --oidc`: OIDC provider URL
- `-d, --database`: Database file path (default: `./.db.toml`)

Additionally you can configure a default user role to avoid specifying `--role` with every command:

```bash
# Set an existing user as default user
socli config set-default -r role
```

With this configuration, you can omit the `--role` parameter:

```bash
# Instead of: socli get --role myuser --uri https://solidserver.com/file.ttl
socli get --uri https://solidserver.com/file.ttl

# Instead of: socli put --role myuser --uri https://solidserver.com/file.ttl --data file.ttl
socli put --uri https://solidserver.com/file.ttl --data file.ttl
```

#### View All Users

```bash
# Display in tabular format
socli status

# Display as JSON
socli status --json
```

### Content Operations

#### Fetch Content (GET)

```bash
# Fetch and display content
socli get --role myuser --uri https://solidserver.com/file.ttl

# Save to file
socli get --role myuser --uri https://solidserver.com/file.ttl --output local.ttl

# Show headers
socli get --role myuser --uri https://solidserver.com/file.ttl --verbose
```

#### Upload Content (PUT)

```bash
# Upload file with public visibility
socli put --role myuser --uri https://solidserver.com/newfile.ttl --data file.ttl --status public

# Upload with private visibility
socli put --role myuser --uri https://solidserver.com/private.ttl --data file.ttl --status private

# Upload from stdin
echo "content" | socli put --role myuser --uri https://solidserver.com/data.txt --data - --status private
```

### Type Index Operations

#### Show Type Indexes

Display public and private type indexes for a WebID:

```bash
# Default turtle format
socli show --role myuser --webid https://solidserver.com/user/profile/card#me

# JSON-LD format
socli show --role myuser --webid https://solidserver.com/user/profile/card#me --format json-ld
```

### Notifications

#### Subscribe to Resources

```bash
socli subscribe --role myuser --uri https://solidserver.com/resource.ttl
```

Options:

- `-i, --inbox-base`: Base inbox URI (default: `http://localhost:3000/dprod/inbox/`)

### Inbox Management

#### Interactive Inbox Viewer

```bash
socli inbox --role myuser
```

This opens an interactive session where you can:

1. View all inbox items
2. Select items to inspect
3. Grant permissions (read/append/write) to resources
4. Skip or go back

## Database File Format

Users are stored in a TOML file (default: `./.db.toml`):

```toml
[[users]]
role = "myuser"
email = "user@example.com"
password = "password"
webid = "https://solidserver.com/user/profile/card#me"
oidc = "https://solidserver.com"

[users.token]
id = "token-id"
secret = "token-secret"
```

## Examples

### End-to-End Example

```bash
# 1. Add a user
socli add \
  --role alice \
  --email alice@example.com \
  --password mypassword \
  --webid https://solid.example.com/alice/profile/card#me \
  --oidc https://solid.example.com

# 2. Check user status
socli status

# 3. Upload a file publicly
socli put \
  --role alice \
  --uri https://solid.example.com/alice/public/hello.txt \
  --data ./dprod.jsonld \
  --status public
# or
echo "Hello Solid World" | socli put \
  --role alice \
  --uri https://solid.example.com/alice/public/hello.txt \

# 4. Fetch the file
socli get --role alice --uri https://solid.example.com/alice/public/hello.txt

# 5. View type indexes
socli show --role alice --webid https://solid.example.com/alice/profile/card#me
```

## Development

This work is far from complete to demonstrate command-line interaction with a solid server. Feature requests are welcome.

# Acknowledgements

- authentication management is handled largely by using Otto-AA's [SolidClientCredentials](https://github.com/Otto-AA/solid-client-credentials-py) library.
