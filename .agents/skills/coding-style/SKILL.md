---
name: coding-style
description: Coding style rules and guidelines for Gatekeeper (following DPDK coding style). Use when writing, modifying, reviewing, or refactoring C code, header files, and build configurations in this repository.
---

# Gatekeeper Coding Style Guide

Gatekeeper strictly follows the **DPDK Coding Style**, which is based on the Linux Kernel coding guidelines and the FreeBSD 7.2 Kernel Developer's Manual (`style(9)`), adapted for high-performance packet processing.

## Reference

- **Original DPDK Coding Style Documentation**:
  https://doc.dpdk.org/guides/contributing/coding_style.html

All agents writing, modifying, or reviewing C code in Gatekeeper must adhere to the rules and conventions below.

---

## Agent Verification Checklist

When generating or editing code, verify:
- [ ] **Indentation**: Hard tabs only for indentation (8-column width). Spaces used *only* for alignment. No spaces before tabs.
- [ ] **Line Length**: Lines do not exceed 80 characters (hard limit: 100 characters when strictly necessary for readability).
- [ ] **Whitespace**: No trailing whitespace on any line. Exactly one newline at the end of the file (no blank lines at file end).
- [ ] **Comments**: Only C-style comments `/* ... */` used. No C++ `//` comments.
- [ ] **Header Includes**: Ordered cleanly: libc/system first, DPDK (`rte_*`) second, third-party libraries third, local Gatekeeper headers last.
- [ ] **Header Guards**: Formatted as `#ifndef _FILE_H_`, `#define _FILE_H_`, and `#endif /* _FILE_H_ */`.
- [ ] **Pointers & Asterisks**: Asterisk attached to variable name: `struct foo *ptr;`, not `struct foo* ptr`.
- [ ] **NULL Checks**: Explicit comparisons against `NULL`: `if (p == NULL)` or `if (p != NULL)`. Never `if (!p)`.
- [ ] **Return Statements**: No parentheses around return value: `return 0;`, never `return (0);`.
- [ ] **Function Definitions**: Return type on its own line preceding the function name. Opening brace `{` on its own line.
- [ ] **Control Flow**: Space after keywords (`if`, `while`, `for`, `switch`). Single-statement bodies omit braces. `else` on the same line as closing brace `} else {`.
- [ ] **Casts & sizeof**: No space after cast `(type)val` or `sizeof(val)`. `sizeof` always has parentheses. No casting of `void *` pointers.

---

## 1. Indentation and Whitespace

### 1.1 Tabs vs Spaces
- Indentation uses **hard tabs** (`\t`). A tab stop is assumed to be **8 characters wide**.
- **Spaces are only for alignment** (e.g., aligning multiline expressions to matching parentheses, or aligning structure fields).
- Never use spaces for indentation. Never place spaces before tabs.

### 1.2 Line Length
- Preferred line length is **at most 80 characters**, including comments.
- Lines up to **100 characters** are acceptable when splitting harms readability.
- When wrapping a long statement, put the operator at the end of the line and indent the continuation line.

### 1.3 Control Statement Continuations
- When continuing conditions across multiple lines in `if`, `while`, or `for` statements, indent the continuation line with **two tabs** (or align with spaces to the opening parenthesis) so it is clearly distinguished from the statement body:

```c
/* Good: double tab distinguishes condition from body */
if (really_long_condition_variable_1 == really_long_condition_variable_2 &&
		flag_is_set) {
	x = y + z;
	a = b + c;
}

/* Good: aligning with spaces to opening parenthesis */
if (really_long_condition_variable_1 == really_long_condition_variable_2 &&
    flag_is_set) {
	x = y + z;
	a = b + c;
}
```

### 1.4 Trailing Whitespace and Newlines
- Do not leave trailing whitespace at the end of any line.
- Files must end with a single newline character. Do not leave blank lines at the end of a file.

---

## 2. Comments

### 2.1 Comment Style
- Use standard C comments `/* ... */`. **Do not use C++ style single-line comments (`//`)**.
- Single-line comments:
  ```c
  /* Most single-line comments look like this. */

  /* * VERY important single-line comments look like this. */
  ```
- Multi-line comments:
  ```c
  /*
   * Multi-line comments look like this. Make them real sentences. Fill
   * them so they look like real paragraphs.
   */
  ```
- Doxygen-like comments (`/** ... */`) must be used for documenting public APIs, interfaces, and exported functions.

### 2.2 License Header
- Every file must begin with a license header comment.
- Followed by a blank line before any `#include` or preprocessor directives.

---

## 3. Preprocessor Directives and Headers

### 3.1 Header Include Order
Group includes into blocks separated by a single blank line, ordered as follows:
1. Standard C library / POSIX system headers (`<stdio.h>`, `<stdlib.h>`, `<arpa/inet.h>`)
2. DPDK headers (`<rte_eal.h>`, `<rte_thash.h>`, `<rte_ether.h>`)
3. Third-party library headers (e.g. Lua, BPF)
4. Local application-specific headers (`"gatekeeper_net.h"`, `"gatekeeper_flow.h"`)

System and library headers use angle brackets `<...>`; local repository headers use double quotes `"..."`:

```c
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>

#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_thash.h>

#include "gatekeeper_net.h"
#include "gatekeeper_main.h"
#include "gatekeeper_flow.h"
```

### 3.2 Header Guards
Headers must be protected against multiple inclusion using the standard format:

```c
#ifndef _GATEKEEPER_FLOW_H_
#define _GATEKEEPER_FLOW_H_

/* Code */

#endif /* _GATEKEEPER_FLOW_H_ */
```

### 3.3 Macros
- Macro names for constants and "unsafe" macros (those with side effects) must be in **ALL_UPPERCASE**.
- Always enclose expressions in outer parentheses:
  ```c
  #define MAX_ITEMS (100)
  #define CALC_OFFSET(base, idx) ((base) + ((idx) * sizeof(uint32_t)))
  ```
- Compound statements in macros must be wrapped in `do { ... } while (0)` without a trailing semicolon:
  ```c
  #define UPDATE_COUNTERS(cnt, delta) do { \
  	(cnt)->pkts += (delta);          \
  	(cnt)->bytes += (delta) * 64;    \
  } while (0)
  ```
- Prefer `enum` for sequential constants and `static inline` functions for logic over macros whenever possible for type-safety and compiler checking.

### 3.4 Conditional Compilation
- Minimize `#ifdef` and conditional compilation.
- If conditionally compiled regions exceed 20 lines or involve nested directives, add a comment after `#else` and `#endif`:
  ```c
  #ifdef CONFIG_FEATURE_X
  /* ... large block ... */
  #else /* !CONFIG_FEATURE_X */
  /* ... */
  #endif /* CONFIG_FEATURE_X */
  ```

---

## 4. Types, Naming, and Declarations

### 4.1 Integer Types
- Always use fixed-width integer types from `<stdint.h>`: `uint8_t`, `uint16_t`, `uint32_t`, `uint64_t`, `int8_t`, `int16_t`, `int32_t`, `int64_t`.
- Do not use old BSD-style types like `u_int32_t` or `u_char`.

### 4.2 Variable and Identifier Naming
- Variable and function names must be in **lowercase with underscores** (`snake_case`).
- **Never** use `CamelCase` or `ALL_UPPERCASE` for variable or function names.
- Public/exported symbols should follow the project namespace conventions.

### 4.3 Pointer Declarations
- The asterisk `*` attaches to the variable name, not the type name:
  ```c
  int *x;             /* Correct: space before asterisk, no space after */
  int* x;             /* Bad */
  int * const x;      /* Correct: space after asterisk when qualifier follows */
  ```

### 4.4 Local Variable Declarations
- Multiple declarations per line are allowed, but do not exceed line length.
- If variables are initialized at declaration, put only **one variable per line**, or initialize only the last variable:
  ```c
  /* Bad: multiple initializations on one line */
  int i = 0, j = 0, k = 0;

  /* Good: one variable per line with initializer */
  char a = 0;
  char b = 0;

  /* Good: only the last variable initialized */
  float x, y = 0.0;
  ```

### 4.5 Structures and Unions
- **Avoid typedefs for structures**. Use `struct foo` directly instead of `typedef struct { ... } foo_t;`:
  ```c
  /* Good */
  struct gatekeeper_flow {
  	uint32_t id;
  };
  struct gatekeeper_flow flow;

  /* Bad */
  typedef struct {
  	uint32_t id;
  } gatekeeper_flow_t;
  ```
- **Member Ordering**:
  1. Order members by **use** (frequently accessed members together).
  2. Order by **size descending** (largest types first: 64-bit, then 32-bit, 16-bit, 8-bit) to minimize alignment padding.
  3. Order alphabetically within the same size category.
- Each member on its own line; align member names with spaces:
  ```c
  struct flow_entry {
  	struct flow_entry *next;  /* List link */
  	uint64_t           pkts;  /* Packet counter */
  	uint32_t           src;   /* IPv4 source */
  	uint32_t           dst;   /* IPv4 destination */
  	uint16_t           port;  /* Layer 4 port */
  	uint8_t            proto; /* Protocol number */
  };
  ```

### 4.6 Enumerations
- Enumeration constants must be **ALL_UPPERCASE**.
- Enums should be used in preference to series of `#define` constants.

---

## 5. Functions

### 5.1 Function Definitions
- The **return type must be on its own line** preceding the function name.
- The **opening brace `{` must be on its own line** at column 0.
- Function body is indented with 1 tab:

```c
/* Correct function definition */
int
flow_cmp(const struct ip_flow *flow1, const struct ip_flow *flow2)
{
	if (flow1->proto != flow2->proto)
		return flow1->proto == RTE_ETHER_TYPE_IPV4 ? -1 : 1;

	return memcmp(flow1, flow2, sizeof(*flow1));
}
```

```c
/* Bad: return type on same line, brace on same line */
int flow_cmp(const struct ip_flow *flow1, const struct ip_flow *flow2) {
	/* ... */
}
```

### 5.2 Function Prototypes
- Prototypes keep the return type and function name on the **same line**:
  ```c
  int flow_cmp(const struct ip_flow *flow1, const struct ip_flow *flow2);
  ```
- Parameter names must be included with their types (e.g. `void func(int fd);`, not `void func(int);`).
- Do not use old K&R function declarations or `__P` macros.

### 5.3 Static and Inline Functions
- Any function local to a single `.c` file **must be declared `static`**.
- Functions declared in headers must be `static inline`:
  ```c
  static inline bool
  flow_equal(const struct ip_flow *flow1, const struct ip_flow *flow2)
  {
  	return flow_cmp(flow1, flow2) == 0;
  }
  ```
- Prefer plain `static inline` and let the compiler optimize. Avoid `__rte_always_inline` unless strictly justified (e.g. constant-folding intrinsics or measured benchmarks).
- Mark cold paths (error recovery, slow path initialization) with `__rte_noinline` to reduce instruction cache pressure.

---

## 6. Control Statements and Loops

### 6.1 Keyword Spacing
- Always place a single space after control keywords: `if`, `while`, `for`, `switch`, `return`.
- Never put a space between a function name and opening parenthesis:
  ```c
  if (ret < 0)              /* Correct */
  if(ret < 0)               /* Bad */
  func(arg1, arg2);         /* Correct */
  func (arg1, arg2);        /* Bad */
  ```

### 6.2 Braces for Control Blocks
- **Omit braces** for single-statement control blocks:
  ```c
  /* Good */
  if (flow == NULL)
  	return -EINVAL;

  /* Bad */
  if (flow == NULL) {
  	return -EINVAL;
  }
  ```
- Use braces if the single statement spans multiple lines, or for nested control statements.
- The `else` keyword is placed on the same line as the closing brace:
  ```c
  if (test) {
  	stmt1;
  	stmt2;
  } else if (other) {
  	stmt3;
  } else {
  	stmt4;
  }
  ```

### 6.3 Loops
- Infinite loops use `for (;;)`, not `while (1)`:
  ```c
  for (;;) {
  	/* Loop body */
  	if (done)
  		break;
  }
  ```

### 6.4 Switch Statements
- Indent the `switch` statement, but do not indent the `case` labels. Indent the case body by 1 tab:
  ```c
  switch (proto) {
  case IPPROTO_TCP:
  	handle_tcp(pkt);
  	break;
  case IPPROTO_UDP:
  	handle_udp(pkt);
  	break;
  case IPPROTO_ICMP:
  	handle_icmp(pkt);
  	/* FALLTHROUGH */
  default:
  	handle_other(pkt);
  	break;
  }
  ```
- Cascade/fallthrough cases must have an explicit `/* FALLTHROUGH */` comment.

---

## 7. Operators, Expressions, and Values

### 7.1 Operator Spacing
- **Unary operators** take no spaces: `!x`, `~x`, `++i`, `--i`, `-val`, `&var`, `*ptr`.
- **Binary operators** have a space on both sides: `a + b`, `x == y`, `val <= limit`, `ptr && ptr->active`.
- **Member access operators** take no spaces: `s.member`, `p->member`.

### 7.2 Parentheses
- Do not use redundant parentheses unless needed for operator precedence or clarity:
  ```c
  /* Good */
  if (a && b)
  return x;

  /* Bad */
  if ((a) && (b))
  return (x);
  ```

### 7.3 Casts and sizeof
- Do not place a space between a cast or `sizeof` and its operand:
  ```c
  uint64_t val = (uint64_t)raw_val;   /* Correct */
  uint64_t val = (uint64_t) raw_val;  /* Bad */

  size = sizeof(struct ip_flow);      /* Correct */
  size = sizeof (struct ip_flow);     /* Bad */
  ```
- Always write `sizeof` with parentheses: `sizeof(var)`, not `sizeof var`.

### 7.4 NULL Comparisons and Booleans
- Compare pointers explicitly against `NULL`:
  ```c
  /* Good */
  if (ptr == NULL)
  if (ptr != NULL)

  /* Bad */
  if (!ptr)
  if (ptr)
  ```
- Only use `!` on boolean variables:
  ```c
  bool is_valid = check_validity();
  if (!is_valid)
  	return -EINVAL;

  /* For characters, compare to '\0' */
  if (*str == '\0')
  	return;
  ```

### 7.5 Return Values
- **Never enclose return values in parentheses**:
  ```c
  return 0;      /* Correct */
  return (0);    /* Bad */
  return ret;    /* Correct */
  return (ret);  /* Bad */
  ```
- **Do not cast `void *` return values**:
  ```c
  /* Good: no cast needed in C */
  struct ip_flow *f = malloc(sizeof(*f));
  struct ip_flow *f = rte_zmalloc("flow", sizeof(*f), 0);

  /* Bad */
  struct ip_flow *f = (struct ip_flow *)malloc(sizeof(*f));
  ```
- Integer-returning functions should follow standard conventions: return `0` on success and `-1` (or negative error number `-errno`, e.g. `-EINVAL`) on failure.
- Functions processing packet bursts return the number of packets processed.
- Functions where error is impossible should return `void`.

### 7.6 Branch Prediction
- In performance-critical data paths, use `likely()` and `unlikely()` macros from `<rte_branch_prediction.h>`:
  ```c
  if (unlikely(flow == NULL))
  	return -EINVAL;

  if (likely(pkt_count > 0))
  	process_burst(pkts, pkt_count);
  ```
- Do not overuse `likely()`/`unlikely()` in non-performance-critical or control plane code.

---

## 8. Gatekeeper Idioms & Best Practices

### 8.1 Logging
- Gatekeeper uses structured logging macros `G_LOG()`:
  ```c
  G_LOG(ERR, "%s(): failed to initialize interface (errno=%d): %s\n",
  	__func__, errno, strerror(errno));
  ```
- Use `unlikely(!G_LOG_CHECK(level))` to guard complex log string preparation when log output is conditionally suppressed.

### 8.2 Compile-Time and Runtime Checks
- Use DPDK compile-time assertions where applicable:
  ```c
  RTE_BUILD_BUG_ON(sizeof(struct ip_flow) != 36);
  ```
- Use DPDK runtime verification for fatal invariant violations:
  ```c
  RTE_VERIFY(ret >= 0 && ret < (int)sizeof(buf));
  ```

### 8.3 Queues and Lists
- Use `<sys/queue.h>` macros (`LIST_HEAD`, `LIST_ENTRY`, `TAILQ_HEAD`, `TAILQ_ENTRY`, etc.) for linked lists rather than custom pointer chasing.
- Use `rte_ring` lockless rings for multi-core packet/event passing across threads.

---

## 9. Python and Build Files

### 9.1 Python
- All Python code must comply with **PEP 8**.
- Maximum line length for Python code is **100 characters** (matching C guidelines).

### 9.2 Meson Build Files
- Indentation uses **4 spaces** (no tabs in Meson files).
- Multi-line statements should use parentheses rather than escaping line breaks.
- Lists of files or dependencies must be **alphabetical**.
- Lists with more than 3 items must place **one entry per line**, with a trailing comma on the last entry:
  ```meson
  sources = files(
      'acl.c',
      'fib.c',
      'flow.c',
      'hash.c',
  )
  ```
