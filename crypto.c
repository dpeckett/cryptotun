// SPDX-License-Identifier: GPL-2.0
#include "crypto.h"
#include "device.h"
#include "messages.h"

static void cryptotun_generate_iv(u64 nonce, u8 *iv)
{
	memset(iv, 0, NONCE_LEN);
	memcpy(iv + 4, &nonce, sizeof(nonce));
}

int cryptotun_encrypt_packet(struct cryptotun_device *tun_dev, const u8 *in,
			     int in_len, u8 *out, int out_len)
{
	struct aead_request *req = NULL;
	struct cryptotun_header *hdr = NULL;
	struct scatterlist sg_in[2], sg_out[2];
	u8 iv[NONCE_LEN];
	int enc_len = in_len + TAG_LEN;
	int total_len = sizeof(struct cryptotun_header) + enc_len;
	int ret = 0;

	if (out_len < total_len)
		return -EINVAL;

	hdr = (struct cryptotun_header *)out;
	hdr->type = cpu_to_be32(CRYPTOTUN_MSG_TYPE_DATA);
	hdr->tunnel_id = cpu_to_be32(0);

	spin_lock(&tun_dev->tx_counter_lock);
	hdr->nonce = cpu_to_be64(((u64)tun_dev->nonce_prefix << 32) |
				 tun_dev->tx_counter++);
	spin_unlock(&tun_dev->tx_counter_lock);

	cryptotun_generate_iv(be64_to_cpu(hdr->nonce), iv);

	req = aead_request_alloc(tun_dev->tx_aead, GFP_KERNEL);
	if (!req)
		return -ENOMEM;

	sg_init_table(sg_in, 2);
	sg_set_buf(&sg_in[0], hdr, sizeof(*hdr));
	sg_set_buf(&sg_in[1], in, in_len);

	sg_init_table(sg_out, 2);
	sg_set_buf(&sg_out[0], hdr, sizeof(*hdr));
	sg_set_buf(&sg_out[1], out + sizeof(*hdr), enc_len);

	aead_request_set_callback(req, 0, NULL, NULL);
	aead_request_set_crypt(req, sg_in, sg_out, in_len, iv);
	aead_request_set_ad(req, sizeof(*hdr));

	ret = crypto_aead_encrypt(req);
	aead_request_free(req);

	if (ret)
		return -EIO;

	return total_len;
}

int cryptotun_decrypt_packet(struct cryptotun_device *tun_dev, const u8 *in,
			     int in_len, u8 *out, int out_len)
{
	struct aead_request *req = NULL;
	struct cryptotun_header *hdr = (struct cryptotun_header *)in;
	const u8 *cipher = in + sizeof(*hdr);
	int cipher_len = in_len - sizeof(*hdr);
	int plain_len = cipher_len - TAG_LEN;
	u8 iv[NONCE_LEN];
	struct scatterlist sg_in[2], sg_out[2];
	int ret;

	if (!tun_dev->rx_aead || in_len < sizeof(*hdr) + TAG_LEN)
		return -EINVAL;

	if (out_len < plain_len)
		return -EMSGSIZE;

	cryptotun_generate_iv(be64_to_cpu(hdr->nonce), iv);

	sg_init_table(sg_in, 2);
	sg_set_buf(&sg_in[0], hdr, sizeof(*hdr));
	sg_set_buf(&sg_in[1], cipher, cipher_len);

	sg_init_table(sg_out, 2);
	sg_set_buf(&sg_out[0], hdr, sizeof(*hdr));
	sg_set_buf(&sg_out[1], out, plain_len);

	req = aead_request_alloc(tun_dev->rx_aead, GFP_KERNEL);
	if (!req)
		return -ENOMEM;

	aead_request_set_callback(req, 0, NULL, NULL);
	aead_request_set_crypt(req, sg_in, sg_out, cipher_len, iv);
	aead_request_set_ad(req, sizeof(*hdr));

	ret = crypto_aead_decrypt(req);
	aead_request_free(req);
	if (ret)
		return -EIO;

	return plain_len;
}
