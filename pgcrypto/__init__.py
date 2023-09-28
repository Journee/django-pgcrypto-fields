from django.conf import settings

DIGEST_SQL = "digest(%s, 'sha512')"
HMAC_SQL = "hmac(%s, '{}', 'sha512')"

PGP_PUB_ENCRYPT_SQL_WITH_NULLIF = "pgp_pub_encrypt(nullif(%s, NULL)::text, dearmor('{}'))"
PGP_SYM_ENCRYPT_SQL_WITH_NULLIF = "pgp_sym_encrypt(nullif(%s, NULL)::text, '{}')"

PGP_PUB_ENCRYPT_SQL = "pgp_pub_encrypt(%s, dearmor('{}'))"

# See docs: https://www.postgresql.org/docs/current/pgcrypto.html

# Choose from algorithms: bf, aes128, aes192, aes256, 3des, cast5
pgp_sym_encrypt_cipher_algo = getattr(settings, 'PGP_SYM_ENCRYPT_CIPHER_ALGO', None)

# Choose from modes: 0 - Without salt.  Dangerous! 1 - With salt but with fixed iteration count. 3 - Variable iteration count.
pgp_sym_encrypt_s2k_mode = getattr(settings, 'PGP_SYM_ENCRYPT_S2K_MODE', None)

# Choose compression:   0 - no compression, 1 - ZIP compression, 2 - ZLIB compression (= ZIP plus meta-data and block CRCs)
pgp_sym_encrypt_compress_algo = getattr(settings, 'PGP_SYM_ENCRYPT_COMPRESS_ALGO', None)

pgp_sym_encrypt_options = []
if pgp_sym_encrypt_cipher_algo:
    pgp_sym_encrypt_options.append(f'cipher-algo={pgp_sym_encrypt_cipher_algo}')
if pgp_sym_encrypt_s2k_mode:
    pgp_sym_encrypt_options.append(f's2k-mode={pgp_sym_encrypt_s2k_mode}')
if pgp_sym_encrypt_compress_algo:
    pgp_sym_encrypt_options.append(f'compress-algo={pgp_sym_encrypt_compress_algo}')

pgp_sym_encrypt_options_str = ", ".join(pgp_sym_encrypt_options)

pgp_sym_encrypt_options_param = f", '{pgp_sym_encrypt_options_str}'" if pgp_sym_encrypt_options else ''

PGP_SYM_ENCRYPT_SQL = "pgp_sym_encrypt(%s, '{}'" + pgp_sym_encrypt_options_param + ")"
PGP_PUB_DECRYPT_SQL = "pgp_pub_decrypt(%s, dearmor('{}'))::%s"
PGP_SYM_DECRYPT_SQL = "pgp_sym_decrypt(%s, '{}')::%s"
