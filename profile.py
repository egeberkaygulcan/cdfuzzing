"""CD-Fuzzing distributed evaluation profile.

Provisions one orchestrator ("head") node plus a set of worker nodes. By default
each of the 12 fuzzers (6 baselines + 6 concept-drift variants) gets 2 worker
nodes (one per repetition), i.e. 24 workers + 1 head = 25 bare-metal nodes.

This file lives at the REPO ROOT so CloudLab's git-based profile creation can
discover it (CloudLab looks for ./profile.py or ./profiles/profile.py). The
boot/orchestration shell scripts it references live in ./cloudlab/.

Model
-----
* The shared CloudLab project NFS (default /proj/cdfuzzing-PG0) and the user home
  (/users/<you>) are mounted on every node, so the cdfuzzing checkout and the
  merge directory are visible cluster-wide.
* Each worker fuzzes ONE fuzzer over all Magma targets on its fast LOCAL disk
  (/mydata blockstore). Docker's data-root is moved to /mydata to avoid the
  small root partition that caused prior disk-exhaustion failures.
* The head node dispatches one campaign per worker over SSH (orchestrate.sh),
  waits for all DONE markers on the shared NFS, then merges the lightweight
  results (everything except the huge queue/ corpora) and runs the analysis.

Usage after the experiment boots (run on the head node)
-------------------------------------------------------
    cd /users/<you>/cdfuzzing/cloudlab
    # dispatch a distributed run labelled "dist1"; 2 nodes/fuzzer => reps 0 and 1
    ./orchestrate.sh --run-id dist1 --timeout 24h
    # ... orchestrate waits for all workers, then merges + analyzes ...
    # results: /proj/cdfuzzing-PG0/distributed/dist1/{ar,plots,status}

Each "node per fuzzer" becomes one repetition (cid) in the merged layout
    ar/<fuzzer>/<target>/<program>/<rep>/
so 2 nodes/fuzzer directly yields the 2-repetition statistical sample the
single-machine setup could not produce in one pass.
"""

import geni.portal as portal
import geni.rspec.pg as pg

# ---------------------------------------------------------------------------
# Canonical fuzzer lists. Order is stable: the head reconstructs worker IPs by
# iterating this same list (fuzzer outer, repetition inner), so profile.py and
# setup-node.sh agree without extra coordination.
# ---------------------------------------------------------------------------
BASELINE_FUZZERS = ["afl", "aflplusplus", "fairfuzz", "moptafl", "aflfast", "honggfuzz"]
CD_FUZZERS = ["aflcd", "aflpluspluscd", "fairfuzzcd", "moptaflcd", "aflfastcd", "honggfuzzcd"]
ALL_FUZZERS = BASELINE_FUZZERS + CD_FUZZERS

pc = portal.Context()
request = pc.makeRequestRSpec()

# --- Parameters ------------------------------------------------------------
# Default is a stock Ubuntu image; setup-node.sh installs Docker at boot, and
# captain builds the Magma target images on the node (Magma does not need to be
# baked into the image). The custom image entry is kept for the case where you
# later snapshot a node -- note the '//' project/image separator (a ':' there is
# the *version* delimiter and produces a 'Could not import .../:0' import error).
imageList = [
    ('urn:publicid:IDN+emulab.net+image+emulab-ops//UBUNTU22-64-STD', 'Ubuntu 22.04 (stock)'),
    ('urn:publicid:IDN+emulab.net+image+emulab-ops//UBUNTU20-64-STD', 'Ubuntu 20.04 (stock)'),
    ('urn:publicid:IDN+emulab.net+image+emulab-ops//UBUNTU24-64-STD', 'Ubuntu 24.04 (stock)'),
    ('urn:publicid:IDN+utah.cloudlab.us+image+cdfuzzing-PG0//DedicatedMachine',
     'cdfuzzing custom snapshot (only if you created one)'),
]

pc.defineParameter("osImage", "OS / disk image", portal.ParameterType.IMAGE,
                   imageList[0], imageList,
                   longDescription="Default is stock Ubuntu 22.04; Docker is installed at boot by "
                                   "cloudlab/setup-node.sh and captain builds the Magma images on "
                                   "the node. Only pick the custom snapshot if you actually created "
                                   "one in the project (Storage -> Disk Images).")

pc.defineParameter("fuzzerSet", "Fuzzers to deploy", portal.ParameterType.STRING, "all",
                   [("all", "All 12 (6 baseline + 6 CD)"),
                    ("baselines", "6 baselines only"),
                    ("cd", "6 CD variants only")],
                   longDescription="Which fuzzers receive worker nodes.")

pc.defineParameter("nodesPerFuzzer", "Worker nodes per fuzzer",
                   portal.ParameterType.INTEGER, 2,
                   longDescription="Each fuzzer gets this many worker nodes; each node is one "
                                   "independent repetition. Total workers = (#fuzzers) x (this). "
                                   "Default 2 with 'all' => 24 workers + 1 head = 25 nodes.")

pc.defineParameter("phystype", "Physical node type",
                   portal.ParameterType.NODETYPE, "",
                   longDescription="e.g. d6515 on Utah. Leave blank to let the mapper choose. "
                                   "For 25 nodes a widely-available type helps mapping succeed.")

pc.defineParameter("blockstoreSize", "Per-node local disk at /mydata (GB)",
                   portal.ParameterType.INTEGER, 100,
                   longDescription="Local blockstore for Docker images and fuzzing workdirs. "
                                   "Set 0 and tick 'Use all available disk' to grab the whole disk.")

pc.defineParameter("blockstoreMax", "Use all available local disk",
                   portal.ParameterType.BOOLEAN, False, advanced=True,
                   longDescription="Allocate all free local disk to /mydata instead of a fixed size.")

pc.defineParameter("repoPath", "cdfuzzing repo path (shared home)",
                   portal.ParameterType.STRING, "/users/eldarfin/cdfuzzing", advanced=True,
                   longDescription="Absolute path to the cdfuzzing checkout on the shared home FS. "
                                   "Boot-time setup is sourced from <repoPath>/cloudlab/.")

pc.defineParameter("sharedDir", "Shared merge directory (project NFS)",
                   portal.ParameterType.STRING, "/proj/cdfuzzing-PG0", advanced=True,
                   longDescription="Project NFS share mounted on every node; merged results and "
                                   "DONE markers are written under here.")

pc.defineParameter("bestEffort", "Best-effort LAN (ignore bandwidth)",
                   portal.ParameterType.BOOLEAN, True, advanced=True,
                   longDescription="Recommended for large node counts so the LAN maps even when "
                                   "the requested bandwidth is unavailable.")

params = pc.bindParameters()

# --- Validate --------------------------------------------------------------
if params.nodesPerFuzzer < 1:
    pc.reportError(portal.ParameterError("Must be >= 1", ["nodesPerFuzzer"]))
if params.blockstoreSize < 0 or params.blockstoreSize > 400:
    pc.reportError(portal.ParameterError("Choose 0..400 GB", ["blockstoreSize"]))
if params.phystype != "" and len(params.phystype.split(",")) != 1:
    pc.reportError(portal.ParameterError("Only a single type is allowed", ["phystype"]))
pc.verifyParameters()

if params.fuzzerSet == "baselines":
    fuzzers = BASELINE_FUZZERS
elif params.fuzzerSet == "cd":
    fuzzers = CD_FUZZERS
else:
    fuzzers = ALL_FUZZERS

total_workers = len(fuzzers) * params.nodesPerFuzzer
if 1 + total_workers > 240:
    pc.reportError(portal.ParameterError(
        "Too many nodes for the /24 LAN address space", ["nodesPerFuzzer"]))

SETUP = params.repoPath + "/cloudlab/setup-node.sh"


def boot_command(setup_args):
    # Wait for the shared home FS (where setup-node.sh lives) to mount, then run it.
    return ("/bin/bash -c '"
            "REPO=\"%s\"; "
            "for i in $(seq 1 60); do [ -f \"$REPO/cloudlab/setup-node.sh\" ] && break; sleep 5; done; "
            "sudo /bin/bash \"$REPO/cloudlab/setup-node.sh\" %s >> /local/setup.log 2>&1"
            "'") % (params.repoPath, setup_args)


# --- Private LAN (static IPs give the head stable SSH targets) --------------
lan = request.LAN("lan")
if params.bestEffort:
    lan.best_effort = True


def make_node(name, ip):
    node = request.RawPC(name)
    if params.osImage and params.osImage != "default":
        node.disk_image = params.osImage
    if params.phystype != "":
        node.hardware_type = params.phystype
    bs = node.Blockstore(name + "-bs", "/mydata")
    bs.size = "0GB" if params.blockstoreMax else (str(params.blockstoreSize) + "GB")
    bs.placement = "any"
    iface = node.addInterface("eth1")
    iface.addAddress(pg.IPv4Address(ip, "255.255.255.0"))
    lan.addInterface(iface)
    return node


# --- Head node -------------------------------------------------------------
head = make_node("head", "192.168.1.1")
head.addService(pg.Execute(shell="bash", command=boot_command(
    "head --fuzzers %s --nodes-per-fuzzer %d --repo %s --shared %s" % (
        ",".join(fuzzers), params.nodesPerFuzzer, params.repoPath, params.sharedDir))))

# --- Worker nodes ----------------------------------------------------------
ip_index = 10  # workers occupy 192.168.1.10 .. 192.168.1.(9+total_workers)
for fuzzer in fuzzers:
    for rep in range(params.nodesPerFuzzer):
        name = "%s-%d" % (fuzzer, rep)
        node = make_node(name, "192.168.1.%d" % ip_index)
        node.addService(pg.Execute(shell="bash", command=boot_command(
            "worker --fuzzer %s --rep %d --repo %s --shared %s" % (
                fuzzer, rep, params.repoPath, params.sharedDir))))
        ip_index += 1

pc.printRequestRSpec(request)
