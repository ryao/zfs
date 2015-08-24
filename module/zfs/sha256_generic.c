void
zio_checksum_SHA256_GENERIC_impl(const void *buf, uint64_t size, zio_cksum_t *zcp)
{
	uint32_t H[8] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
	    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };
	uint8_t pad[128];
	int i, padsize;

	for (i = 0; i < (size & ~63ULL); i += 64)
		SHA256Transform(H, (uint8_t *)buf + i);

	for (padsize = 0; i < size; i++)
		pad[padsize++] = *((uint8_t *)buf + i);

	for (pad[padsize++] = 0x80; (padsize & 63) != 56; padsize++)
		pad[padsize] = 0;

	for (i = 56; i >= 0; i -= 8)
		pad[padsize++] = (size << 3) >> i;

	for (i = 0; i < padsize; i += 64)
		SHA256Transform(H, pad + i);

	ZIO_SET_CHECKSUM(zcp,
	    (uint64_t)H[0] << 32 | H[1],
	    (uint64_t)H[2] << 32 | H[3],
	    (uint64_t)H[4] << 32 | H[5],
	    (uint64_t)H[6] << 32 | H[7]);
}
