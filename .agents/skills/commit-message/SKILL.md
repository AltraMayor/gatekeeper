---
name: commit-message
description: Rules and guidelines for generating Git commit messages in Gatekeeper. Use when writing, formatting, or reviewing Git commit messages for this repository.
---

# Gatekeeper Commit Message Guidelines

All commit messages in Gatekeeper must follow the project's established conventions.

## Format

```text
<subsystem>: <short summary in imperative mood>

<detailed description of changes>

<optional issue references>
```

## Rules

1. **Subsystem Prefix (`<subsystem>`)**:
   - Matches the affected subsystem, functional block, or directory in lowercase.
   - **Libraries**: For modules under `lib/`, use the path prefix (e.g. `lib/net`, `lib/fib`, `lib/hash`, `lib/rib`, `lib/mailbox`, `lib/flow`, `lib/acl`).
   - **Functional Blocks and Daemons**: Use the block or tool name in lowercase (e.g. `gk`, `gt`, `cps`, `sol`, `lls`, `ggu`, `dyc`, `gkctl`).
   - **Supporting Subsystems**: `bpf`, `lua`, `log`, `style`, `debian`, `github`.
   - **Core and Build**: For project-wide changes, build scripts, or documentation, use the component or filename (e.g. `gatekeeper`, `Makefile`, `setup.sh`, `README`, `.gitignore`, `dpdk`).
   - **Isolated Files/Headers**: For changes isolated to a specific public header or standalone utility, use the file path or utility name (e.g. `include/gatekeeper_net.h`, `generate_if_map`).

2. **Subject Line**:
   - **Format**: `<subsystem>: <imperative summary>` (separated by a colon and a single space).
   - **Casing**: Start the summary with a lowercase letter (e.g. `lib/net: adjust dataroom based on MTU`), unless the first word is a case-sensitive code identifier, macro, or proper noun (e.g. `log: merge MAIN_LOG() into G_LOG()`, `style: rename lua_State from l to L`, `README: update URLs to use HTTPS`).
   - **Mood**: Use the imperative mood (e.g. `add`, `fix`, `update`, `remove`, `adopt`, `avoid`, `replace`, `centralize`, `rewrite`, `drop`, not `added`, `fixes`, `updating`).
   - **Punctuation**: Do not end the subject line with a period.
   - **Length**: Keep the subject line concise (under 72 characters, ideally 50–60 characters).
   - **Function and Manual References**: When mentioning functions or commands in the subject, adhere to the reference rules below (e.g. `gkctl: perror(3) already adds a newline`, `lib/net: set all RSS fields in check_if_rss()`).

3. **Function, Command, and Symbol References**:
   - **Internal / Project Functions**:
     Always append empty parentheses `()` to function names and function-like macros:
     - Examples: `check_if_rss()`, `create_pktmbuf_pool()`, `sol_stage2()`, `rte_gettid()`, `MAIN_LOG()`.
   - **Standard Library Functions, System Calls, and System Commands**:
     Always append the manual section number in parentheses after the name of standard library functions, POSIX functions, system calls, system commands, and OS capabilities:
     - **Section 1 (User Commands)**: `ls(1)`, `grep(1)`
     - **Section 2 (System Calls)**: `getrandom(2)`, `prctl(2)`, `umask(2)`, `lchown(2)`, `fchmod(2)`, `syscall(2)`
     - **Section 3 (C / Library Functions)**: `free(3)`, `perror(3)`, `strncpy(3)`, `sscanf(3)`
     - **Section 7 (Conventions / Overviews)**: `capabilities(7)`
     - **Section 8 (System Administration Commands)**: `mount(8)`, `systemd(8)`
   - **Types, Structs, and Macros**:
     Mention types with their C specifiers (e.g. `struct gatekeeper_if`, `lua_State`, `rib_address_t`), and macros/constants in uppercase (e.g. `RTE_ETH_TX_OFFLOAD_MULTI_SEGS`, `PR_SET_KEEPCAPS`, `NULL`, `-EEXIST`).
   - **Plain Text Style**:
     Do not use Markdown backticks in commit messages. Write code identifiers, function names, file names, compiler options (e.g. `-Wstringop-truncation`), and directives (e.g. `#define _GNU_SOURCE`) as plain text. Single quotes (`'...'`) may be used for quoting exact phrases or shell commands where clarity is needed.

4. **Message Body**:
   - **Separation**: Separate the subject from the body with a blank line.
   - **Line Wrapping**: Hard-wrap all body lines at 72 characters.
   - **Structure**:
     - State the problem, limitation, or background context first (e.g. what fails, what warning appears, or what behavior is missing).
     - State the solution and technical rationale (what changed and why this approach was chosen).
   - **Lists**: When breaking down multiple steps or changes, use numbered lists (`1. ...`, `2. ...`) or bullet points (`- ...`).
   - **Diagnostics**: Compiler warnings, error messages, and log snippets may be included verbatim in the body to document the problem clearly.

5. **Issue References**:
   - **Closing Issues**: When closing an issue, use the project's standard formula at the end of the body (separated by a blank line):
     ```text
     This commit closes #<issue-number>.
     ```
     or:
     ```text
     This patch closes #<issue-number>.
     ```
   - **Closing Multiple Issues**:
     ```text
     This commit closes #<n1>, closes #<n2>, closes #<n3>.
     ```
   - **Non-Closing References**: When referencing an issue without closing it:
     ```text
     See issue #<issue-number> for more information.
     ```
     or:
     ```text
     This patch pushes issue #<issue-number> forward.
     ```

## Examples

### Example 1: Function name with `()` and standard library call with man section
```text
lib/fib: fib_free() must be okay with uninitialized FIBs

When a Gatekeeper server is set to work with either IPv4 or
IPv6 only, fib_free() is called on an uninitialized FIB.
This patch avoids a segmentation fault by following the example of
free(3) that ignores NULL.
```

### Example 2: System calls with section numbers and numbered list
```text
cps: replace DPDK's KNI library with virtio-user

File cps/main.c is the only user of functions kni_process_arp() and
kni_process_nd(). Moreover, the only relationship between
these functions and KNI is the fact that they process packets
read from KNI interfaces.

This commit
1. moves kni_process_arp() and kni_process_nd() from
   cps/kni.c to cps/main.c;
2. makes those functions static; and
3. renames those functions to process_arp() and process_nd().

DPDK dropped its KNI library at version 23.11.
This commit replaces DPDK's KNI library with virtio-user.

This commit closes #481, closes #570, closes #585, closes #674.
```

### Example 3: System call in subject and body
```text
gatekeeper: call system call getrandom(2) directly

When randomize_rss_key() was first written,
the system call getrandom(2) had no wrapper.

This commit replaces syscall(2) with getrandom(2).
```

### Example 4: Compiler warning, plain text symbols, and issue closing
```text
lib/net: give an informative error when not enough queues

While tuning the number of instances of the functional blocks,
the configuration may exceed the maximum number of queues that
the NICs support. When this happens, the error message in the log
is not informative. For example:

Ethdev port_id=0 nb_rx_queues=43 > 8
Main/0 2024-06-25 17:07:22 ERR init_iface(back): failed to configure interface (errno=22): Invalid argument

This commit identifies the problem and gives a helpful error message:

Main/0 2024-06-25 17:38:22 ERR check_if_queues(back): the current configuration requires 43 RX queues, but the interface supports at most 8 RX queues. It may be possible to reduce the number of instances of the GK or GT functional block to reduce the number of queues. If not, more capable NICs are needed.
Main/0 2024-06-25 17:38:22 ERR init_iface(back): interface doesn't support a critical hardware capability (errno=28): No space left on device

This commit closes #620.
```
