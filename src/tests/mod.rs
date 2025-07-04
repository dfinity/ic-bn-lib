use indoc::indoc;

#[cfg(all(
    any(
        all(target_os = "linux", target_arch = "x86_64"),
        all(target_os = "macos", target_arch = "aarch64")
    ),
    feature = "acme"
))]
pub mod pebble;

pub const TEST_KEY: &str = indoc! {"
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCd/7NXWeENaITm
YU+eWMJEJMZa6v74g70RpZlprQzx148U0QOKEw/r6mmdSlbN4wsbb9lUu3zmXXpv
YDAHYuOTYsDWcuNJXP/gCnPrD2wU8lJt3C5blmeU/9+0U6/ppRmu6kf/jmm7CMBn
owI0+kdvTF7sbpiUBXTDujXNsqtX0FaksILc9ZAqpUCC2gqRcOXahzT2vnvJ2N+2
bhveG+eB0/5oZcKgx0D4QgjR9k1+thWOQZUCJMg32OYSk4e57WhOQxu9Kh5N2MU1
Ff3fhCYXzg7/GhJtWyDmjt1vNBwGW9Zn0BicySdcVFPCmRW3/rZrSpnwvsEnpIuy
KGq+NMSXAgMBAAECggEAKYtxTFAxWZW4kF1ZEqFzH3juAT0WYyE8x1WcY8mhhDvy
fv5AqH8/qgBe2gGQlp2TL5k2881C184PohaQOnj5rykB3MGj2wgNrgsBlPberBlV
rFZ/iAyh2u93EpMIx+5mNPScjumTCp+P/BBERcrjmrPhp9ii3RUcMVUWzaoj3Lhc
wa5trC1r7UqbUZeO7NaVA7cGETZLVm8U7NaL8ccb1dKASUzrC9QCy9VVekJbb2S7
h38MELR9wvTGS7s4hXQGejb8vEDuXcZzWIFg3YMkJPIyGLAEaRynfeAHm/ji48U0
zh1ba3CWE/6z6nayDPqWqrwic4Hff6Mz+SIWAz2LyQKBgQDcdeWweNRVXhVkcFUP
JNpUiLOF5j3f4nqZwk7j5hQBxcXilYO/lmrcimvhvJ3ox97GfqCkvEQM8thTnPmi
JBagynOfIaUK2qdVwS1BbZ2JpYe3k/rO+iSKtRO4mF94cHgFIafPb5qt0fFz9bDS
7D2lnWSbveMvb+mZsp/+FZx2DwKBgQC3eBhAbOSrSGuh7KOuWsav8pROMdcsESpz
j8el1iEklRsklYiNrVsztlZtNUXE2zSHeNPsGENDGlvKG8qD/vbcdTFsYa1H8Hk5
NydTLAb0/Bm256Xee1Dm5Wt2yG2aLfc9eG0trJz8VgBDhDlulnjo2kavhWIpTBNm
0WmkMQsQ+QKBgQDYXd1PlUbPgcb9DEJu2nxs+r02bQHM+TnaLhm/EdAQ7UmJV7Q2
FCpMyI2YvsU78O1zYlPHWf5vtucZKLbXqxOKOye+xgZ04KPaRf1keXBj51GLmnBN
MrMqbw0r3l/UlI02fBF2RNJKRgHzDO6+E51tLUvQjkyqAewCLI1ZkVw9gQKBgD0F
J2O+E+vX4VxwnRvvOyfn0WWUdBFHAEyBJJDGgC1vniBzz3/3iV7QpTwbPMI1eeoY
yLs8cpqN2LuGtLtkAGzgWXjHn99OXrMl4eFqwkGW22KW9vbhIs44vZ47GSDvasy6
Ee3f/DJ81AegoY1jZIFln57fCP/dOpK20aD3YsvZAoGBAKgaWVYbROCRJ6C8CQGd
yetoZ8n25E7O5JtyKSNGwiQyD0IURgLuotiBpQvCCz9HGS53E6HLzBCc4jZc3GDq
qVDS5cIgcfWAOBalBQ+JxoHsnLRGXeBBKwvaJB+EzlrV8st1dCmM4gukElBJm/PZ
TvEPeiHG81OgB1RPgUt3DVIf
-----END PRIVATE KEY-----
"};

pub const TEST_CERT: &str = indoc! {"
-----BEGIN CERTIFICATE-----
MIIC6TCCAdGgAwIBAgIUK60AjMl8YTJ5nWViMweY043y6/EwDQYJKoZIhvcNAQEL
BQAwDzENMAsGA1UEAwwEbm92ZzAeFw0yMzAxMDkyMTM5NTZaFw0zMzAxMDYyMTM5
NTZaMA8xDTALBgNVBAMMBG5vdmcwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQCd/7NXWeENaITmYU+eWMJEJMZa6v74g70RpZlprQzx148U0QOKEw/r6mmd
SlbN4wsbb9lUu3zmXXpvYDAHYuOTYsDWcuNJXP/gCnPrD2wU8lJt3C5blmeU/9+0
U6/ppRmu6kf/jmm7CMBnowI0+kdvTF7sbpiUBXTDujXNsqtX0FaksILc9ZAqpUCC
2gqRcOXahzT2vnvJ2N+2bhveG+eB0/5oZcKgx0D4QgjR9k1+thWOQZUCJMg32OYS
k4e57WhOQxu9Kh5N2MU1Ff3fhCYXzg7/GhJtWyDmjt1vNBwGW9Zn0BicySdcVFPC
mRW3/rZrSpnwvsEnpIuyKGq+NMSXAgMBAAGjPTA7MAkGA1UdEwQCMAAwDwYDVR0R
BAgwBoIEbm92ZzAdBgNVHQ4EFgQUYHN6l0ihbfbLQXqnKPltmv9DWDkwDQYJKoZI
hvcNAQELBQADggEBAFBvyns/lJZ+zB4/Tmx3YUryji20XUNwhtlBC6V7rdWCXneY
kqKVgbyDZ+XAYX2eL3o1gcv+XJxQgHfL+OqHJCVbK2kkYVSCW38WNVZb+oeTp/w3
pgtmg91JcCjFEw2doqImLZLQDX6KK1gDGdTQ2dtisFcxGEkMUyjzqmZmZNzl+u7d
JeDygLfGrMleO7ij2hP2vEfgkGbbvM+JCTav0B91Rj8/CbJHBwr8/CW4BJTjsqZC
mglNb9+hY8N6XAxntoqZsFzuDyDx7ZSxeAW0yVRemrIPSgcPwpLDBFm4dCSwUHJN
ujBjp7DRCQgg8uUq+0FMQ63ioZoR5mXQ5hzmTqk=
-----END CERTIFICATE-----
"};
