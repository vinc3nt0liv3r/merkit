# Remote testing on a temporary Windows machine

The `remote-test` workflow starts a short-lived Windows machine on GitHub, builds Merkit on it, creates a
throw-away test directory, and opens Remote Desktop to it. You connect over a private
[Tailscale](https://tailscale.com) network. Nothing is exposed to the internet.

## What you get

| | |
|---|---|
| Machine | GitHub-hosted Windows runner, deleted when the session ends |
| Test directory | AD LDS instance on `localhost:50389`, base DN `DC=merkit,DC=test` |
| Sample data | OUs *Workstations*, *Servers*, *Users* (with *Helpdesk*, *Sales*) and *Groups*, with permissions that trigger the linter (missing deletion protection, a deleted group's SID, Everyone with write access, a duplicate entry) |
| Sign-in | user `merkit`, password from your `RDP_PASSWORD` secret |
| Lifetime | 10 to 120 minutes (you choose), ends early after 20 idle minutes or when `C:\stop-session.txt` exists |

### What this test directory is not

AD LDS uses the same LDAP protocol and security descriptors as Active Directory, so it is a good test for reading
and changing permissions, backups, rollback and the linter. It is **not a domain**: no Kerberos domain, no domain
controller locator, no computer accounts, no real domain SIDs. A GitHub runner cannot be a real domain controller,
because promoting one needs a restart and the runner is lost on restart.

Before you use Merkit on a real domain, test it once on a real AD DS forest in a throw-away virtual machine
(Hyper-V or VirtualBox with a free Windows Server evaluation ISO). `tools/lab/New-LabForest.ps1` sets that up.
Keep that VM off your production network.

## One-time setup (about 15 minutes)

### 1. Tailscale account and your PC

1. Create a free Tailscale account and install Tailscale on the PC you will connect from.
2. Sign in on that PC.

### 2. Restrict the temporary machine (important)

In the Tailscale admin console, open **Access controls** and make sure the policy contains the lines below.
Without them the temporary runner could be allowed to reach your other devices.

```jsonc
{
  // Only you may create nodes with this tag.
  "tagOwners": {
    "tag:merkit-ci": ["autogroup:admin"]
  },

  "grants": [
    // Your own devices can reach each other.
    { "src": ["autogroup:member"], "dst": ["autogroup:self"], "ip": ["*"] },

    // Your devices can open Remote Desktop to the temporary machine and nothing else on it.
    { "src": ["autogroup:member"], "dst": ["tag:merkit-ci"], "ip": ["tcp:3389"] }
  ]
  // There is deliberately NO grant with "src": ["tag:merkit-ci"], so the runner cannot start connections to anything.
}
```

If your existing policy has a rule that allows everything (`"src": ["*"], "dst": ["*"]`), replace it with the
rules above or the restriction does not hold.

### 3. A Tailscale OAuth client for GitHub

1. In the admin console open **Settings** and find **OAuth clients** (it may be listed under trust credentials).
2. Create a client with the scope **Auth Keys: Write** and the tag **`tag:merkit-ci`**.
3. Copy the client ID and the client secret. The secret is shown once.

Tailscale also supports workload identity federation, which avoids storing a long-lived secret. The workflow uses
the OAuth client because it is simpler to set up; you can switch later.

### 4. GitHub secrets

Repository **Settings → Secrets and variables → Actions → New repository secret**. Create three:

| Name | Value |
|---|---|
| `TS_OAUTH_CLIENT_ID` | the client ID from step 3 |
| `TS_OAUTH_SECRET` | the client secret from step 3 |
| `RDP_PASSWORD` | a new random password, at least 16 characters, not used anywhere else |

The password is never printed. Do not paste it into chats, issues or commit messages.

## Starting a session

1. Repository **Actions → remote-test → Run workflow**. Choose the minutes and whether to fill the sample data.
2. Wait for the step **Show how to connect** (about 5 to 8 minutes). It prints an address like `100.x.y.z`.
3. On your PC (with Tailscale running) open **Remote Desktop Connection**, enter that address, user `merkit`, and your
   `RDP_PASSWORD`.
4. The repository is in `C:\a\merkit\merkit`. Test directory: server `localhost`, port `50389`, base DN
   `DC=merkit,DC=test`.

To end early, create an empty file `C:\stop-session.txt` on the machine, or cancel the run in GitHub.

## How it is locked down

- Only the repository owner can start the workflow, and it runs only when started by hand.
- Remote Desktop requires Network Level Authentication and TLS.
- The Windows firewall accepts Remote Desktop only from Tailscale addresses.
- The `merkit` account locks for 30 minutes after 5 wrong passwords.
- The Tailscale node is ephemeral and tagged. The grants above let it accept Remote Desktop and nothing else.
- When the session ends the workflow turns Remote Desktop off, deletes the account and logs the node out.
- Everything on the machine is deleted by GitHub afterwards. Do not store anything you want to keep there.

## Cost and limits

Windows minutes count double on private repositories (a free account has 2,000 included minutes a month, so about
1,000 Windows minutes). A 60-minute session plus setup uses about 140 of them. Public repositories do not use up
included minutes. Use the machine only to test this project, which is what GitHub's terms allow.
