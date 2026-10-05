# SSH CAPTCHA — Manual Setup (AlmaLinux 9)

Adds a visual CAPTCHA to SSH login. CAPTCHA must be solved before the password prompt appears. Failed CAPTCHA terminates the connection immediately — no password prompt is ever shown.

```
SSH CAPTCHA VERIFICATION

 ##  #### ###   ##  ####
#  # #    #  # #  # #
#### ###  ###  #  # ###
#  # #    # #  #  # #
#  # #### #  #  ##  ####

Enter captcha (1/3): _
```

**Authentication flow:**

```
SSH connect
    │
    ▼
CAPTCHA challenge (max 3 attempts)
    │
    ├── correct ──► password prompt (max 3 attempts)
    │                   │
    │                   ├── correct ──► shell
    │                   └── 3 wrong  ──► connection closed
    │
    └── 3 wrong ──► connection closed (no password prompt)
```

---

## Requirements

- AlmaLinux 9
- Root access

---

## Step 1 — Switch to root

```bash
sudo su
```

All following steps require root.

---

## Step 2 — Install dependencies

```bash
dnf install -y openssh-server gcc pam-devel
```

---

## Step 3 — Write the C source

Create `/usr/local/src/pam_ssh_captcha.c`:

```c
#define _GNU_SOURCE

#include <ctype.h>
#include <errno.h>
#include <security/pam_appl.h>
#include <security/pam_ext.h>
#include <security/pam_modules.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/random.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#define MAX_CAPTCHA_LEN     12
#define MIN_CAPTCHA_LEN     4
#define GLYPH_HEIGHT        5
#define GLYPH_WIDTH         5
#define CANVAS_HEIGHT       9
#define SPACING             2
#define CANVAS_WIDTH        (MAX_CAPTCHA_LEN * (GLYPH_WIDTH + SPACING) + SPACING)
#define ART_BUFFER_SIZE     ((CANVAS_WIDTH * 3 + 1) * CANVAS_HEIGHT + 1)
#define MESSAGE_BUFFER_SIZE (ART_BUFFER_SIZE + 512)
#define FILLED_CELL         "\xE2\x96\x88"

struct glyph { char ch; const char *rows[GLYPH_HEIGHT]; };

static const struct glyph font[] = {
    {'A', {" ##  ", "#  # ", "#### ", "#  # ", "#  # "}},
    {'B', {"###  ", "#  # ", "###  ", "#  # ", "###  "}},
    {'C', {" ### ", "#    ", "#    ", "#    ", " ### "}},
    {'D', {"###  ", "#  # ", "#  # ", "#  # ", "###  "}},
    {'E', {"#### ", "#    ", "###  ", "#    ", "#### "}},
    {'F', {"#### ", "#    ", "###  ", "#    ", "#    "}},
    {'G', {" ### ", "#    ", "# ## ", "#  # ", " ### "}},
    {'H', {"#  # ", "#  # ", "#### ", "#  # ", "#  # "}},
    {'J', {"  ## ", "   # ", "   # ", "#  # ", " ##  "}},
    {'K', {"#  # ", "# #  ", "##   ", "# #  ", "#  # "}},
    {'L', {"#    ", "#    ", "#    ", "#    ", "#### "}},
    {'M', {"#   #", "## ##", "# # #", "#   #", "#   #"}},
    {'N', {"#   #", "##  #", "# # #", "#  ##", "#   #"}},
    {'P', {"###  ", "#  # ", "###  ", "#    ", "#    "}},
    {'Q', {" ##  ", "#  # ", "#  # ", "# #  ", " # # "}},
    {'R', {"###  ", "#  # ", "###  ", "# #  ", "#  # "}},
    {'S', {" ### ", "#    ", " ##  ", "   # ", "###  "}},
    {'T', {"#####", "  #  ", "  #  ", "  #  ", "  #  "}},
    {'U', {"#  # ", "#  # ", "#  # ", "#  # ", " ##  "}},
    {'V', {"#   #", "#   #", "#   #", " # # ", "  #  "}},
    {'W', {"#   #", "#   #", "# # #", "## ##", "#   #"}},
    {'X', {"#   #", " # # ", "  #  ", " # # ", "#   #"}},
    {'Y', {"#   #", " # # ", "  #  ", "  #  ", "  #  "}},
    {'Z', {"#####", "   # ", "  #  ", " #   ", "#####"}},
    {'2', {" ##  ", "#  # ", "  #  ", " #   ", "#### "}},
    {'3', {"###  ", "   # ", " ##  ", "   # ", "###  "}},
    {'4', {"#  # ", "#  # ", "#### ", "   # ", "   # "}},
    {'5', {"#### ", "#    ", "###  ", "   # ", "###  "}},
    {'6', {" ##  ", "#    ", "###  ", "#  # ", " ##  "}},
    {'7', {"#### ", "   # ", "  #  ", " #   ", " #   "}},
    {'8', {" ##  ", "#  # ", " ##  ", "#  # ", " ##  "}},
    {'9', {" ##  ", "#  # ", " ### ", "   # ", " ##  "}},
};

/* I, O, 1 excluded to avoid visual ambiguity */
static const char captcha_chars[] = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
static const char noise_chars[]   = ".:;~*+=-";

static unsigned int random_u32(void)
{
    unsigned int v = 0;
    if (getrandom(&v, sizeof(v), 0) == (ssize_t)sizeof(v)) return v;
    return ((unsigned int)random() << 16) ^ (unsigned int)random()
         ^ (unsigned int)time(NULL) ^ (unsigned int)getpid();
}

static int random_below(int upper)
{
    if (upper <= 1) return 0;
    return (int)(random_u32() % (unsigned int)upper);
}

static const struct glyph *find_glyph(char ch)
{
    size_t i;
    for (i = 0; i < sizeof(font)/sizeof(font[0]); i++)
        if (font[i].ch == ch) return &font[i];
    return NULL;
}

static void generate_text(char *out, int length)
{
    int i, n = (int)strlen(captcha_chars);
    for (i = 0; i < length; i++) out[i] = captcha_chars[random_below(n)];
    out[length] = '\0';
}

static void render_art(const char *text, int noise_pct, char *out, size_t outsz)
{
    char canvas[CANVAS_HEIGHT][CANVAS_WIDTH + 1];
    size_t pos = 0;
    int r, c, i, len = (int)strlen(text);
    int aw = len * (GLYPH_WIDTH + SPACING) + SPACING;
    if (aw > CANVAS_WIDTH) aw = CANVAS_WIDTH;

    memset(canvas, ' ', sizeof(canvas));
    for (r = 0; r < CANVAS_HEIGHT; r++) canvas[r][aw] = '\0';

    c = SPACING;
    for (i = 0; i < len; i++) {
        const struct glyph *g = find_glyph(text[i]);
        int yo = random_below(2), gr, gc;
        if (!g) { c += GLYPH_WIDTH + SPACING; continue; }
        for (gr = 0; gr < GLYPH_HEIGHT; gr++)
            for (gc = 0; gc < GLYPH_WIDTH; gc++) {
                int y = yo+gr, x = c+gc;
                if (y>=0 && y<CANVAS_HEIGHT && x>=0 && x<aw)
                    canvas[y][x] = g->rows[gr][gc];
            }
        c += GLYPH_WIDTH + SPACING;
    }

    if (noise_pct > 0) {
        int nc = (int)strlen(noise_chars);
        for (r = 0; r < CANVAS_HEIGHT; r++)
            for (c = 0; c < aw; c++)
                if (canvas[r][c]==' ' && random_below(100)<noise_pct)
                    canvas[r][c] = noise_chars[random_below(nc)];
    }

    out[0] = '\0';
    for (r = 0; r < CANVAS_HEIGHT; r++) {
        for (c = 0; c < aw; c++) {
            const char *cell = (canvas[r][c]=='#') ? FILLED_CELL : NULL;
            size_t need = cell ? strlen(cell) : 1;
            if (pos+need+1 >= outsz) { out[outsz-1]='\0'; return; }
            if (cell) { memcpy(out+pos, cell, need); pos += need; }
            else        out[pos++] = canvas[r][c];
        }
        if (pos+1 >= outsz) { out[outsz-1]='\0'; return; }
        out[pos++] = '\n'; out[pos] = '\0';
    }
}

static int converse(pam_handle_t *pamh, int style, const char *text, char **response)
{
    const struct pam_conv    *conv = NULL;
    const struct pam_message  msg  = { style, text };
    const struct pam_message *msgp = &msg;
    struct pam_response      *resp = NULL;
    int rc;

    rc = pam_get_item(pamh, PAM_CONV, (const void **)&conv);
    if (rc != PAM_SUCCESS || !conv || !conv->conv) return PAM_CONV_ERR;

    rc = conv->conv(1, &msgp, &resp, conv->appdata_ptr);
    if (rc != PAM_SUCCESS) return rc;

    if (response) {
        if (!resp) { *response = NULL; return PAM_CONV_ERR; }
        *response = resp[0].resp;
    } else if (resp) {
        if (resp[0].resp) free(resp[0].resp);
    }
    free(resp);
    return PAM_SUCCESS;
}

static int send_info(pam_handle_t *p, const char *t)
    { return converse(p, PAM_TEXT_INFO,      t, NULL); }
static int send_error(pam_handle_t *p, const char *t)
    { return converse(p, PAM_ERROR_MSG,      t, NULL); }
static int prompt_answer(pam_handle_t *p, const char *t, char **a)
    { return converse(p, PAM_PROMPT_ECHO_ON, t, a); }

static void normalize_answer(char *s)
{
    char *src=s, *dst=s;
    if (!s) return;
    while (*src) {
        if (!isspace((unsigned char)*src))
            *dst++ = (char)toupper((unsigned char)*src);
        src++;
    }
    *dst = '\0';
}

static int parse_int_arg(const char *arg, const char *name,
                         int fallback, int min, int max)
{
    size_t nlen = strlen(name); char *end; long v;
    if (strncmp(arg, name, nlen) || arg[nlen] != '=') return fallback;
    errno = 0; v = strtol(arg+nlen+1, &end, 10);
    if (errno || end == arg+nlen+1 || *end) return fallback;
    if (v < min) return min;
    if (v > max) return max;
    return (int)v;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags,
                                   int argc, const char **argv)
{
    int length=6, attempts=3, noise=12, i;
    unsigned int seed;
    (void)flags;

    seed = random_u32();
    srandom((unsigned int)time(NULL) ^ (unsigned int)getpid() ^ seed);

    for (i=0; i<argc; i++) {
        length   = parse_int_arg(argv[i], "length",   length,   MIN_CAPTCHA_LEN, MAX_CAPTCHA_LEN);
        attempts = parse_int_arg(argv[i], "attempts", attempts, 1, 10);
        noise    = parse_int_arg(argv[i], "noise",    noise,    0, 35);
    }

    for (i=1; i<=attempts; i++) {
        char  expected[MAX_CAPTCHA_LEN+1];
        char  art[ART_BUFFER_SIZE];
        char  message[MESSAGE_BUFFER_SIZE];
        char  prompt[96];
        char *answer = NULL;
        int   rc, correct;

        generate_text(expected, length);
        render_art(expected, noise, art, sizeof(art));
        snprintf(message, sizeof(message),
                 "\nSSH CAPTCHA VERIFICATION\n\n%s\n"
                 "Type the text shown above before password authentication.\n", art);

        rc = send_info(pamh, message);
        if (rc != PAM_SUCCESS) {
            explicit_bzero(expected, sizeof(expected));
            return rc;
        }

        snprintf(prompt, sizeof(prompt), "Enter captcha (%d/%d): ", i, attempts);
        rc = prompt_answer(pamh, prompt, &answer);
        if (rc != PAM_SUCCESS || !answer) {
            if (answer) { explicit_bzero(answer, strlen(answer)); free(answer); }
            explicit_bzero(expected, sizeof(expected));
            return PAM_AUTH_ERR;
        }

        normalize_answer(answer);
        correct = (strcmp(answer, expected) == 0);
        explicit_bzero(answer,   strlen(answer));
        explicit_bzero(expected, sizeof(expected));
        free(answer);

        if (correct) {
            send_info(pamh, "CAPTCHA correct. Continue with password.\n");
            return PAM_SUCCESS;
        }
        if (i < attempts) send_error(pamh, "CAPTCHA incorrect. Try again.\n");
    }

    pam_syslog(pamh, LOG_NOTICE, "SSH CAPTCHA failed");
    send_error(pamh, "CAPTCHA failed. Access denied.\n");
    return PAM_AUTH_ERR;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags,
                               int argc, const char **argv)
{
    (void)pamh; (void)flags; (void)argc; (void)argv;
    return PAM_SUCCESS;
}
```

---

## Step 4 — Compile the module

```bash
gcc -Wall -Wextra -O2 -fPIC -shared \
    -fstack-protector-strong \
    -D_FORTIFY_SOURCE=2 \
    -fno-common \
    -Wl,-z,relro -Wl,-z,now \
    /usr/local/src/pam_ssh_captcha.c \
    -o /usr/lib64/security/pam_ssh_captcha.so \
    -lpam

chmod 755 /usr/lib64/security/pam_ssh_captcha.so
restorecon /usr/lib64/security/pam_ssh_captcha.so 2>/dev/null || true
```

Verify:

```bash
file /usr/lib64/security/pam_ssh_captcha.so
```

Expected: `ELF 64-bit LSB shared object, x86-64`

---

## Step 5 — Configure PAM

Edit `/etc/pam.d/sshd`. Insert the CAPTCHA line **directly before** the `auth substack password-auth` line.

> **The control flag must be `requisite`, not `required`.**
>
> - `required` — marks auth failed but continues running remaining modules. The password prompt still appears before the final denial.
> - `requisite` — stops the PAM stack immediately on failure. No further modules run, so no password prompt is shown.

Your file should look like this after editing:

```
#%PAM-1.0
auth       requisite    pam_ssh_captcha.so  length=6  attempts=3  noise=12
auth       substack     password-auth
auth       include      postlogin
account    required     pam_sepermit.so
...
```

Verify the position and that only one captcha line exists:

```bash
grep -n 'captcha\|password-auth' /etc/pam.d/sshd
```

Expected:

```
2:auth       requisite    pam_ssh_captcha.so  length=6  attempts=3  noise=12
3:auth       substack     password-auth
```

---

## Step 6 — Configure sshd

AlmaLinux 9 ships `/etc/ssh/sshd_config.d/50-redhat.conf`. OpenSSH processes drop-in files in alphabetical order and uses **first-match wins** — the first file to set a directive locks it in and later files are ignored for that directive. To ensure our settings take effect, the file must sort **before** `50-redhat.conf`.

Create `/etc/ssh/sshd_config.d/10-captcha.conf`:

```bash
cat > /etc/ssh/sshd_config.d/10-captcha.conf << 'EOF'
# Processed before 50-redhat.conf — first-match wins
UsePAM                        yes
KbdInteractiveAuthentication  yes
PasswordAuthentication        no
EOF
```

> Do **not** set `AuthenticationMethods` here. On AlmaLinux 9 the crypto policy loaded by `50-redhat.conf` causes sshd to reject it with `AuthenticationMethods cannot be satisfied`.

---

## Step 7 — Generate host keys

If SSH host keys do not exist (fresh install or container environment):

```bash
ssh-keygen -A
mkdir -p /run/sshd
```

`ssh-keygen -A` skips any key type that already exists — safe to run regardless.

---

## Step 8 — Validate and restart sshd

```bash
sshd -t
```

Check effective values before restarting:

```bash
sshd -T | grep -Ei 'usepam|kbdinteractive|passwordauth'
```

Expected:

```
usepam yes
kbdinteractiveauthentication yes
passwordauthentication no
```

If `kbdinteractiveauthentication` shows `no`, see the troubleshooting section.

Restart:

```bash
systemctl restart sshd
systemctl status sshd --no-pager
```

---

## Step 9 — Check the firewall

```bash
firewall-cmd --query-service=ssh
```

If the output is `no`:

```bash
firewall-cmd --add-service=ssh --permanent
firewall-cmd --reload
```

---

## Test

**Keep your current session open.** Open a second terminal:

```bash
ssh -o PreferredAuthentications=keyboard-interactive \
    -o PubkeyAuthentication=no \
    your-user@127.0.0.1
```

**Correct CAPTCHA path:**

```
CAPTCHA art appears
Enter captcha (1/3): [correct answer]
CAPTCHA correct. Continue with password.
Password: [correct password]
[shell]
```

**Failed CAPTCHA path (connection must close with no password prompt):**

```
Enter captcha (1/3): [wrong]
CAPTCHA incorrect. Try again.
Enter captcha (2/3): [wrong]
CAPTCHA incorrect. Try again.
Enter captcha (3/3): [wrong]
CAPTCHA failed. Access denied.
Connection closed.
```

No password prompt must appear after CAPTCHA failure.

---

## Configuration

Arguments on the PAM line in `/etc/pam.d/sshd`. Changes apply to new connections immediately — no recompile or sshd restart needed.

| Argument | Default | Range | Description |
|----------|---------|-------|-------------|
| `length` | `6` | 4–12 | Number of characters rendered |
| `attempts` | `3` | 1–10 | Wrong-answer retries before denial |
| `noise` | `12` | 0–35 | Percentage of blank cells filled with noise |

Example:

```
auth  requisite  pam_ssh_captcha.so  length=8  attempts=5  noise=0
```

---

## Uninstall

```bash
# 1. Remove the PAM line
sed -i '/pam_ssh_captcha/d' /etc/pam.d/sshd

# 2. Remove the sshd drop-in
rm -f /etc/ssh/sshd_config.d/10-captcha.conf

# 3. Remove the module and source
rm -f /usr/lib64/security/pam_ssh_captcha.so
rm -f /usr/local/src/pam_ssh_captcha.c

# 4. Restart
sshd -t && systemctl restart sshd
```

---

## Troubleshooting

**Password prompt appears after CAPTCHA failure**

The PAM control flag is `required` instead of `requisite`. Edit `/etc/pam.d/sshd` and change the word:

```
# wrong
auth  required   pam_ssh_captcha.so ...

# correct
auth  requisite  pam_ssh_captcha.so ...
```

No restart needed — takes effect on the next connection.

**`kbdinteractiveauthentication no` in `sshd -T` output**

A file in `sshd_config.d/` sorted before `10-captcha.conf` is locking the value to `no` first. Find it:

```bash
grep -ri 'KbdInteractiveAuthentication' /etc/ssh/sshd_config.d/
```

Rename our file to a lower number so it sorts first:

```bash
mv /etc/ssh/sshd_config.d/10-captcha.conf /etc/ssh/sshd_config.d/05-captcha.conf
sshd -t && systemctl restart sshd
```

**`Permission denied (publickey,gssapi-keyex,gssapi-with-mic)` — no CAPTCHA shown**

`kbdinteractiveauthentication` is still `no`. The server is not offering keyboard-interactive at all. See fix above.

**`sshd: no hostkeys available`**

```bash
ssh-keygen -A
mkdir -p /run/sshd
sshd -t && systemctl restart sshd
```

**CAPTCHA line in wrong position**

The captcha line must appear before `auth substack password-auth`, not before any `account`, `password`, or `session` lines. Check:

```bash
grep -n 'captcha\|password-auth' /etc/pam.d/sshd
```

If wrong, remove and re-insert manually:

```bash
sed -i '/pam_ssh_captcha/d' /etc/pam.d/sshd
# edit /etc/pam.d/sshd and insert before auth substack password-auth
```

**Locked out**

Access via console or cloud serial access:

```bash
sed -i '/pam_ssh_captcha/d' /etc/pam.d/sshd
rm -f /etc/ssh/sshd_config.d/10-captcha.conf
sshd -t && systemctl restart sshd
```
