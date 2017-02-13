/**
 * collectd - src/xfrm.c
 * Copyright (C) 2017 Martin Nowak
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; only version 2 of the License is applicable.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA
 *
 * Authors:
 *   Martin Nowak <code at dawg.eu>
 **/

#include "collectd.h"

#include "common.h"
#include "plugin.h"

#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/xfrm.h>
#include <libmnl/libmnl.h>

static struct mnl_socket *nl;

static void submit_one(const char *type, const char *type_instance, gauge_t value) {
  value_t values[1];
  value_list_t vl = VALUE_LIST_INIT;

  values[0].gauge = value;

  vl.values = values;
  vl.values_len = 1;
  sstrncpy (vl.host, hostname_g, sizeof (vl.host));
  sstrncpy (vl.plugin, "xfrm", sizeof(vl.plugin));
  sstrncpy (vl.type, type, sizeof(vl.type));

  if (type_instance != NULL)
    sstrncpy(vl.type_instance, type_instance, sizeof(vl.type_instance));

  plugin_dispatch_values(&vl);
} /* void submit_one */

#define CASE_ATTR(TYPE, ptr, attr)                                      \
    case TYPE:                                                          \
    if (mnl_attr_validate2(attr, MNL_TYPE_UNSPEC, sizeof(*ptr)) < 0) {  \
        ERROR("xfrm plugin: policy_cb: "#TYPE" mnl_attr_validate2 "  \
              "failed.");                                               \
        return MNL_CB_ERROR;                                            \
    }                                                                   \
    ptr = mnl_attr_get_payload(attr);

static int policy_cb(const struct nlmsghdr *nlh,
                          void *args __attribute__((unused))) {
    struct nlattr *attr;
    struct xfrmu_spdinfo *si;
    struct xfrmu_spdhinfo *sh;
    mnl_attr_for_each(attr, nlh, sizeof(__u32)) {
        switch (mnl_attr_get_type(attr))
        {
        CASE_ATTR(XFRMA_SPD_INFO, si, attr)
            submit_one("count", "spd_in", si->incnt);
            submit_one("count", "spd_out", si->outcnt);
            submit_one("count", "spd_fwd", si->fwdcnt);
            submit_one("count", "spd_socket_in", si->inscnt);
            submit_one("count", "spd_socket_out", si->outscnt);
            submit_one("count", "spd_socket_fwd", si->fwdscnt);
            break;

        CASE_ATTR(XFRMA_SPD_HINFO, sh, attr)
            submit_one("count", "spd_hash_buckets", sh->spdhcnt);
            submit_one("count", "spd_hash_buckets_max", sh->spdhmcnt);
            break;

        default:
            continue;
        }
    }
    return MNL_CB_STOP;
}

static int state_cb(const struct nlmsghdr *nlh,
                          void *args __attribute__((unused))) {
    struct nlattr *attr;
    __u32 *sadcnt;
    struct xfrmu_sadhinfo *sh;
    mnl_attr_for_each(attr, nlh, sizeof(__u32)) {
        switch (mnl_attr_get_type(attr))
        {
        CASE_ATTR(XFRMA_SAD_CNT, sadcnt, attr)
            submit_one("count", "sad", *sadcnt);
            break;

        CASE_ATTR(XFRMA_SAD_HINFO, sh, attr)
            submit_one("count", "sad_hash_buckets", sh->sadhcnt);
            submit_one("count", "sad_hash_buckets_max", sh->sadhmcnt);
            break;

        default:
            continue;
        }
    }
    return MNL_CB_STOP;
}

static int xfrm_init(void) {
  nl = mnl_socket_open(NETLINK_XFRM);
  if (nl == NULL) {
    ERROR("xfrm plugin: xfrm_init: mnl_socket_open failed.");
    return (-1);
  }

  if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
    ERROR("xfrm plugin: xfrm_init: mnl_socket_bind failed.");
    return (-1);
  }

  return (0);
} /* int xfrm_init */

static int xfrm_request(__u16 nlmsg_type, const uint8_t *p_hdr, size_t hdr_size, mnl_cb_t response_cb) {
  char buf[MNL_SOCKET_BUFFER_SIZE];
  struct nlmsghdr *nlh;
  unsigned int portid = mnl_socket_get_portid(nl);

  nlh = mnl_nlmsg_put_header(buf);
  nlh->nlmsg_type = nlmsg_type;
  nlh->nlmsg_flags = NLM_F_REQUEST;
  unsigned int seq = nlh->nlmsg_seq = time(NULL);
  uint8_t *p = mnl_nlmsg_put_extra_header(nlh, hdr_size);
  memcpy(p, p_hdr, hdr_size);

  if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
    ERROR("xfrm plugin: xfrm_read: mnl_socket_sendto failed.");
    return (-1);
  }

  int ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
  while (ret > 0) {
    ret = mnl_cb_run(buf, ret, seq, portid, response_cb, NULL);
    if (ret <= MNL_CB_STOP)
      break;
    ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
  }
  if (ret < 0) {
    ERROR("xfrm plugin: xfrm_read: mnl_socket_recvfrom failed.");
    return (-1);
  }
  return (0);
} /* int xfrm_request */

static int xfrm_read(void) {
  const __u32 flags = 0xFFFFFFFF;
  int ret;
  if ((ret = xfrm_request(XFRM_MSG_GETSPDINFO, (const uint8_t*) &flags, sizeof(flags), policy_cb)))
      return ret;
  if ((ret = xfrm_request(XFRM_MSG_GETSADINFO, (const uint8_t*) &flags, sizeof(flags), state_cb)))
      return ret;
  return 0;
} /* int xfrm_read */

static int xfrm_shutdown(void) {
  if (nl) {
    mnl_socket_close(nl);
    nl = NULL;
  }

  return (0);
} /* int xfrm_shutdown */

void module_register(void) {
  //plugin_register_config("xfrm", xfrm_config, config_keys, config_keys_num);
  plugin_register_init("xfrm", xfrm_init);
  plugin_register_read("xfrm", xfrm_read);
  plugin_register_shutdown("xfrm", xfrm_shutdown);
} /* void module_register */
