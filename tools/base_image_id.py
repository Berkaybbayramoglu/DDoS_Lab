#!/usr/bin/env python3
"""Prints the short image id Labtainer expects for a base image, e.g. labtainers/labtainer.network3.

Labtainer compares the `base` label of a published lab image with `docker images -q <base>` on the
student's machine. With Docker's classic image store that id is the image's config digest; newer
Docker versions with the containerd image store show the manifest digest instead. To get the same
value on any build machine, the config digest is read from Docker Hub (linux/amd64), as Labtainer
itself reads image data from the registry.
  usage: base_image_id.py <repository>[:tag]
"""
import json
import sys
import urllib.request

ref = sys.argv[1]
repo, _, tag = ref.partition(":")
tag = tag or "latest"
if "/" not in repo:
    repo = "library/" + repo


def get(url, accept=None, token=None):
    req = urllib.request.Request(url)
    if accept:
        req.add_header("Accept", accept)
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)


token = get(f"https://auth.docker.io/token?service=registry.docker.io&scope=repository:{repo}:pull")["token"]
kinds = ", ".join(["application/vnd.oci.image.index.v1+json",
                   "application/vnd.docker.distribution.manifest.list.v2+json",
                   "application/vnd.oci.image.manifest.v1+json",
                   "application/vnd.docker.distribution.manifest.v2+json"])
m = get(f"https://registry-1.docker.io/v2/{repo}/manifests/{tag}", kinds, token)
if "manifests" in m:                                   # multi-platform index: take linux/amd64
    amd64 = next(x for x in m["manifests"]
                 if x.get("platform", {}).get("os") == "linux" and x["platform"].get("architecture") == "amd64")
    m = get(f"https://registry-1.docker.io/v2/{repo}/manifests/{amd64['digest']}", kinds, token)
print(m["config"]["digest"].split(":", 1)[1][:12])
