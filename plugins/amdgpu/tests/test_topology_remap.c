/**************************************************************************************************
 * GPU groups remapping unit tests
 *
 * Test cases for GPU topology group remapping when there are P2P iolinks between the GPUs. GPUs are
 * considered to be grouped when they are connected via a XGMI bridge.
 *
 * When a GPU has large BAR enabled and its full address space can be accessed by another GPU (i.e
 * its address is within 40/44/48-bits address limitation of the other GPU), then
 * the other GPU will have an P2P-PCIe to this GPU.
 *
 * When GPUs have large BAR, but one GPU cannot address the full address another, then there is no
 * iolink-PCIe from this GPU to the other GPU. This GPU still has to be remapped to a GPU with
 * large BAR on restore. The other GPU could still have an iolink-PCIe to this GPU. This would
 * result in a uni-directional P2P-PCIe.
 *
 *
 * In general, the GPU ID's have the following format to ease debugging:
 * WXYZ where:
 * W = A in the source topology, B in the destination topology
 * X = Unused
 * Y = Hive number
 * Z = GPU number
 *
 * e.g A017 = GPU in source topology, Hive number 1 (2nd hive), GPU number 7 (8th GPU)
 *
 *
 * Test 0: 8 GPUs in 2 XGMI hives (full P2P-PCIe)
 *	2 XGMI hives of 4 GPUs
 *	Each hives have different type of GPUs
 *	All 8 GPUs have P2P-PCIe links
 *	2 CPU's - each cpu can access alternate GPUs
 *
 *	Src Topology:
 *	  Hive-0 has 4 GPUs device-id 0xD000
 *	  Hive-1 has 4 GPUs device-id 0xD001
 *
 *	Dest Topology:
 *	  Hive-0 has 4 GPUs device-id 0xD001
 *	  Hive-1 has 4 GPUs device-id 0xD000
 *
 *      EXPECT: SUCCESS
 *	  GPUs in Hive-0 in Src Topology should be mapped to GPUs in Hive-1 in Dest Topology and
 *	  GPUs in Hive-1 in Src Topology should be mapped to GPUs in Hive-0. So that the device-id's
 *	  match.
 *
 *
 * Test 1: 8 GPUs in 2 XGMI hives (partial P2P-PCIe case 1)
 *	2 XGMI hives of 4 GPUs
 *	All 8 GPUs have the same device-id
 *
 *	Src Topology:
 *	  Hive-0 has 4 GPUs
 *	  Hive-1 has 4 GPUs
 *	  GPUs 0, 1, 2, 3, 4, 5 have P2P-PCIe links
 *	  GPUs 7, 8 do not have P2P-PCIe links
 *
 *	Dest Topology:
 *	  Same as Src Topology
 *
 *	EXPECT: SUCCESS
 *
 *
 * Test 2: 8 GPUs in 2 XGMI hives (partial P2P-PCIe case 1)
 *	Same as test 1 but each hive have different device-id's for each hive.
 *
 *	Src Topology:
 *	  Hive-0 has 4 GPUs with device-id 0xD000
 *	  Hive-1 has 4 GPUs with device-id 0xD001
 *	  GPUs 0, 1, 2, 3, 4, 5 have P2P-PCIe links
 *	  GPUs 7, 8 do not have P2P-PCIe links
 *
 *	Dest Topology:
 *	  Hive-0 has 4 GPUs with device-id 0xD001
 *	  Hive-1 has 4 GPUs with device-id 0xD000
 *	  GPUs 0, 1, 2, 3, 4, 5 have P2P-PCIe links
 *	  GPUs 7, 8 do not have P2P-PCIe links
 *
 *	EXPECT: FAIL
 *	  It is not possible to map the GPUs because Src:Hive-0 would have to be mapped to
 *	  Dest:Hive-1 to be able to match the P2P-PCIe links, but Src:Hive-0 and Dest:Hive-1 have
 *	  different device-id's.
 *
 *
 * Test 3:8 GPUs in 2 XGMI hives (partial P2P-PCIe case 2)
 *	2 XGMI hives of 4 GPUs
 *	1 GPU in each hive has a P2P-PCIe link but at different indexes within the hive.
 *
 *	Src Topology:
 *	  Hive-0: Has 4 GPUs with device-id 0xD000.
 *		  Only GPU-2(A002) has bi-directional P2P-PCIe link.
 *
 *	  Hive-1: Has 4 GPUs with device-id 0xD001.
 *		  Only GPU-7(A017) has bi-directional P2P-PCIe link.
 *
 *	Dest Topology:
 *	  Hive-0: Has 4 GPUs with device-id 0xD000.
 *		  Only GPU-0(B000) has bi-directional P2P-PCIe link.
 *
 *	  Hive-1: Has 4 GPUs with device-id 0xD001.
 *		  Only GPU-5(B015) has bi-directional P2P-PCIe link.
 *
 *
 *	EXPECT: SUCCESS
 *	  Only possible map for A002 is B000 because B000 is the only dest GPU with device-id 0xD000
 *	  that has a P2P-PCIe link.
 *	  Only possible map for A017 is B015 because B015 is the only dest GPU with device-id 0xD001
 *	  that has a P2P-PCIe link.
 *
 *
 * Test 4:8 GPU's in 2 XGMI hives (partial P2P-PCIe case 2)
 *	Similar to Test 3 but not possible to map because one CPU iolink is uni-directional
 *
 *	Src Topology:
 *	  Hive-0: Has 4 GPUs with device-id 0xD000.
 *		  Only GPU-2(A002) has bi-directional P2P-PCIe link.
 *
 *	  Hive-1: Has 4 GPUs with device-id 0xD001.
 *		  Only GPU-7(A017) has bi-directional P2P-PCIe link.
 *
 *	Dest Topology:
 *	  Hive-0: Has 4 GPUs with device-id 0xD000.
 *		  Only GPU-0(B000) has bi-directional P2P-PCIe link.
 *
 *	  Hive-1: Has 4 GPUs with device-id 0xD001.
 *		  Only GPU-5(B014) has uni-directional P2P-PCIe link.
 *
 *	EXPECT: FAIL
 *
 *
 * Test 5: 8 GPUs with 1 XGMI hive
 *	4 GPUs in 1 XGMI hive, 4 GPUs have no XGMI bridge. Tests combination of XGMI and non-XGMI.
 *	All 8 GPUs have P2P-PCIe links
 *
 *	Src Topology:
 *	  Hive-0: Has 4 GPUs
 *	  4 Other GPUs are not part of a XGMI hive
 *
 *	Dest Topology:
 *	   Same as src topology
 *
 *	EXPECT: SUCCESS
 *
 *
 * Test 6: 5 GPUs (mix and match GPU types and partial P2P-PCIe links)
 *	No XGMI bridges
 *	First 4 GPUs have P2P-PCIe links
 *	1 GPU has different device-id's at different locations
 *
 *	Src Topology:
 *	  GPU-0, GPU-1, GPU-3 has device-id 0xD000
 *	  GPU-2, GPU-4 has device-id 0xD001
 *
 *	Dest Topology:
 *	  GPU-0, GPU-2, GPU-3 has device-id 0xD000
 *	  GPU-1, GPU-4 has device-id 0xD001
 *
 *	EXPECT: SUCCESS
 *	  Mapping needs to be able to map A001->B002 and A002->B001.
 *
 *
 **************************************************************************************************
 * Tests where restore node is more capable than checkpointed node
 * In the following tests, the destination topology is more P2P-links than the source topology, so
 * the mapping should succeed, even though the user application will probably not be able to take
 * advantage of the extra links.
 *
 * Test 7: 8 GPUs (ignore XGMI bridge on restore node)
 *
 *	Src Topology:
 *	  Hive-0: GPU-0, GPU-1, GPU-2, GPU-3
 *	  No XGMI bridge: GPU-4, GPU-5, GPU-6, GPU-7
 *
 *	Dest Topology:
 *	  Hive-0: GPU-0, GPU-1, GPU-2, GPU-3
 *	  Hive-1: GPU-4, GPU-5, GPU-6, GPU-7
 *
 *	EXPECT: SUCCESS
 *	  Mapping should succeed, because destination GPUs GPU-4, GPU-5, GPU-6, GPU-7 are more
 *	  capable than source GPUs GPU-4, GPU-5, GPU-6, GPU-7.
 *	  User application will probably not take advantage of XGMI links in Hive-1.
 *
 *
 * Test 8: 5 GPUs (4 GPUs with P2P-PCIe links vs 3 GPUs with P2P-PCIe links)
 *
 *	Src Topology:
 *	  GPU-0, GPU-1, GPU-2 have bi-directional links
 *	  GPU-3, GPU-4 have unidirectional links
 *
 *	Dest Topology:
 *	  GPU-0, GPU-1, GPU-2, GPU-3 have bi-directional links
 *	  GPU-4 have unidirectional links
 *
 *	EXPECT: SUCCESS
 *	  Mapping should succeed because destination GPU-3 can replace source GPU-3.
 *
 **************************************************************************************************/

#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include "common/list.h"

#include "amdgpu_plugin_topology.h"

#define pr_err(...)   fprintf(stdout, "ERR:" __VA_ARGS__)
#define pr_info(...)  fprintf(stdout, "INFO:" __VA_ARGS__)
#define pr_debug(...) fprintf(stdout, "DBG:" __VA_ARGS__)

int verify_maps(const struct device_maps *maps, uint32_t num_cpus, uint32_t num_gpus)
{
	struct id_map *map;

	/* TODO: This merely checks that all nodes have been mapped. We should add individual
	 * verification functions for each test to tests the mappings are correct
	 */

	list_for_each_entry(map, &maps->cpu_maps, listm) {
		if (num_cpus-- == 0) {
			pr_err("Results had more mappings than number of CPUs\n");
			return -EINVAL;
		}
	}
	if (num_cpus > 0) {
		pr_err("Results did not map all CPUs\n");
		return -EINVAL;
	}

	list_for_each_entry(map, &maps->gpu_maps, listm) {
		if (num_gpus-- == 0) {
			pr_err("Results had more mappings than number of GPUs\n");
			return -EINVAL;
		}
	}
	if (num_gpus > 0) {
		pr_err("Results did not map all GPUs\n");
		return -EINVAL;
	}
	return 0;
}

int test_0(void)
{
	int ret = 0;
	struct device_maps maps;

	struct tp_node *node_gpus[8];
	struct tp_node *node_cpus[2];

	struct tp_system tp_src = { 0 };
	struct tp_system tp_dest = { 0 };

	/* Fill src struct */
	topology_init(&tp_src);
	tp_src.parsed = true;

	node_cpus[0] = sys_add_node(&tp_src, 0, 0);
	node_cpus[0]->cpu_cores_count = 1;
	node_cpus[1] = sys_add_node(&tp_src, 1, 0);
	node_cpus[1]->cpu_cores_count = 1;

	for (int i = 0; i < 4; i++) {
		node_gpus[i] = sys_add_node(&tp_src, i + 2, 0xA000 + i);
		node_gpus[i]->device_id = 0xD000;
		node_add_iolink(node_gpus[i], TOPO_IOLINK_TYPE_PCIE, i & 1);
		node_add_iolink(node_cpus[i & 1], TOPO_IOLINK_TYPE_PCIE, i + 2);
	}
	for (int i = 0; i < 4; i++) {
		for (int j = 1; j < 4; j++)
			node_add_iolink(node_gpus[i], TOPO_IOLINK_TYPE_XGMI, ((i + j) % 4) + 2);
		for (int j = 6; j < 10; j++)
			node_add_iolink(node_gpus[i], TOPO_IOLINK_TYPE_PCIE, j);
	}

	for (int i = 4; i < 8; i++) {
		node_gpus[i] = sys_add_node(&tp_src, i + 2, 0xA010 + i);
		node_gpus[i]->device_id = 0xD001;
		node_add_iolink(node_gpus[i], TOPO_IOLINK_TYPE_PCIE, i & 1);
		node_add_iolink(node_cpus[i & 1], TOPO_IOLINK_TYPE_PCIE, i + 2);
	}
	for (int i = 4; i < 8; i++) {
		for (int j = 1; j < 4; j++)
			node_add_iolink(node_gpus[i], TOPO_IOLINK_TYPE_XGMI, ((i + j) % 4) + 6);
		for (int j = 2; j < 6; j++)
			node_add_iolink(node_gpus[i], TOPO_IOLINK_TYPE_PCIE, j);
	}

	/* Fill dest struct */
	topology_init(&tp_dest);
	tp_dest.parsed = true;

	node_cpus[0] = sys_add_node(&tp_dest, 0, 0);
	node_cpus[0]->cpu_cores_count = 1;
	node_cpus[1] = sys_add_node(&tp_dest, 1, 0);
	node_cpus[1]->cpu_cores_count = 1;

	for (int i = 0; i < 4; i++) {
		node_gpus[i] = sys_add_node(&tp_dest, i + 2, 0xB000 + i);
		node_gpus[i]->device_id = 0xD001;
		node_add_iolink(node_gpus[i], TOPO_IOLINK_TYPE_PCIE, i & 1);
		node_add_iolink(node_cpus[i & 1], TOPO_IOLINK_TYPE_PCIE, i + 2);
	}
	for (int i = 0; i < 4; i++) {
		for (int j = 1; j < 4; j++)
			node_add_iolink(node_gpus[i], TOPO_IOLINK_TYPE_XGMI, ((i + j) % 4) + 2);
		for (int j = 6; j < 10; j++)
			node_add_iolink(node_gpus[i], TOPO_IOLINK_TYPE_PCIE, j);
	}

	for (int i = 4; i < 8; i++) {
		node_gpus[i] = sys_add_node(&tp_dest, i + 2, 0xB010 + i);
		node_gpus[i]->device_id = 0xD000;
		node_add_iolink(node_gpus[i], TOPO_IOLINK_TYPE_PCIE, i & 1);
		node_add_iolink(node_cpus[i & 1], TOPO_IOLINK_TYPE_PCIE, i + 2);
	}
	for (int i = 4; i < 8; i++) {
		for (int j = 1; j < 4; j++)
			node_add_iolink(node_gpus[i], TOPO_IOLINK_TYPE_XGMI, ((i + j) % 4) + 6);
		for (int j = 2; j < 6; j++)
			node_add_iolink(node_gpus[i], TOPO_IOLINK_TYPE_PCIE, j);
	}

	ret = set_restore_gpu_maps(&tp_src, &tp_dest, &maps);
	if (!ret) {
		if (verify_maps(&maps, ARRAY_SIZE(node_cpus), ARRAY_SIZE(node_gpus))) {
			pr_err("Mapping returned success, but results had errors\n");
			ret = -1;
		}
	}
	topology_free(&tp_src);
	topology_free(&tp_dest);
	maps_free(&maps);
	return ret;
}

int test_1(void)
{
	int ret = 0;
	struct device_maps maps;

	struct tp_node *node_gpus[8];
	struct tp_node *node_cpus[2];

	struct tp_system tp_src = { 0 };
	struct tp_system tp_dest = { 0 };

	/* Fill src struct */
	topology_init(&tp_src);
	tp_src.parsed = true;

	node_cpus[0] = sys_add_node(&tp_src, 0, 0);
	node_cpus[0]->cpu_cores_count = 1;
	node_cpus[1] = sys_add_node(&tp_src, 1, 0);
	node_cpus[1]->cpu_cores_count = 1;

	for (int i = 0; i < 4; i++) {
		node_gpus[i] = sys_add_node(&tp_src, i + 2, 0xA000 + i);
		node_gpus[i]->device_id = 0xD000;
		node_add_iolink(node_gpus[i], TOPO_IOLINK_TYPE_PCIE, i & 1);
		node_add_iolink(node_cpus[i & 1], TOPO_IOLINK_TYPE_PCIE, i + 2);
	}
	for (int i = 0; i < 4; i++) {
		for (int j = 1; j < 4; j++)
			node_add_iolink(node_gpus[i], TOPO_IOLINK_TYPE_XGMI, ((i + j) % 4) + 2);
		for (int j = 6; j < 8; j++)
			node_add_iolink(node_gpus[i], TOPO_IOLINK_TYPE_PCIE, j);
	}

	for (int i = 4; i < 8; i++) {
		node_gpus[i] = sys_add_node(&tp_src, i + 2, 0xA010 + i);
		node_gpus[i]->device_id = 0xD000;

		node_add_iolink(node_gpus[i], TOPO_IOLINK_TYPE_PCIE, i & 1);
		if (i < 6)
			node_add_iolink(node_cpus[i & 1], TOPO_IOLINK_TYPE_PCIE, i + 2);
	}
	for (int i = 4; i < 8; i++) {
		for (int j = 1; j < 4; j++)
			node_add_iolink(node_gpus[i], TOPO_IOLINK_TYPE_XGMI, ((i + j) % 4) + 6);

		for (int j = 2; j < 6; j++)
			node_add_iolink(node_gpus[i], TOPO_IOLINK_TYPE_PCIE, j);
	}

	/* Fill dest struct */
	topology_init(&tp_dest);
	tp_dest.parsed = true;

	node_cpus[0] = sys_add_node(&tp_dest, 0, 0);
	node_cpus[0]->cpu_cores_count = 1;
	node_cpus[1] = sys_add_node(&tp_dest, 1, 0);
	node_cpus[1]->cpu_cores_count = 1;

	for (int i = 0; i < 4; i++) {
		node_gpus[i] = sys_add_node(&tp_dest, i + 2, 0xB000 + i);
		node_gpus[i]->device_id = 0xD000;
		node_add_iolink(node_gpus[i], TOPO_IOLINK_TYPE_PCIE, i & 1);
		node_add_iolink(node_cpus[i & 1], TOPO_IOLINK_TYPE_PCIE, i + 2);
	}
	for (int i = 0; i < 4; i++) {
		for (int j = 1; j < 4; j++)
			node_add_iolink(node_gpus[i], TOPO_IOLINK_TYPE_XGMI, ((i + j) % 4) + 2);
		for (int j = 6; j < 8; j++)
			node_add_iolink(node_gpus[i], TOPO_IOLINK_TYPE_PCIE, j);
	}

	for (int i = 4; i < 8; i++) {
		node_gpus[i] = sys_add_node(&tp_dest, i + 2, 0xB010 + i);
		node_gpus[i]->device_id = 0xD000;

		node_add_iolink(node_gpus[i], TOPO_IOLINK_TYPE_PCIE, i & 1);
		if (i < 6)
			node_add_iolink(node_cpus[i & 1], TOPO_IOLINK_TYPE_PCIE, i + 2);
	}
	for (int i = 4; i < 8; i++) {
		for (int j = 1; j < 4; j++)
			node_add_iolink(node_gpus[i], TOPO_IOLINK_TYPE_XGMI, ((i + j) % 4) + 6);
		for (int j = 2; j < 6; j++)
			node_add_iolink(node_gpus[i], TOPO_IOLINK_TYPE_PCIE, j);
	}

	ret = set_restore_gpu_maps(&tp_src, &tp_dest, &maps);
	if (!ret) {
		if (verify_maps(&maps, ARRAY_SIZE(node_cpus), ARRAY_SIZE(node_gpus))) {
			pr_err("Mapping returned success, but results had errors\n");
			ret = -1;
		}
	}
	topology_free(&tp_src);
	topology_free(&tp_dest);
	maps_free(&maps);
	return ret;
}

int test_2(void)
{
	int ret = 0;
	struct device_maps maps;

	struct tp_node *node_gpus[8];
	struct tp_node *node_cpus[2];

	struct tp_system tp_src = { 0 };
	struct tp_system tp_dest = { 0 };

	/* Fill src struct */
	topology_init(&tp_src);
	tp_src.parsed = true;

	node_cpus[0] = sys_add_node(&tp_src, 0, 0);
	node_cpus[0]->cpu_cores_count = 1;
	node_cpus[1] = sys_add_node(&tp_src, 1, 0);
	node_cpus[1]->cpu_cores_count = 1;

	for (int i = 0; i < 4; i++) {
		node_gpus[i] = sys_add_node(&tp_src, i + 2, 0xA000 + i);
		node_gpus[i]->device_id = 0xD000;
		node_add_iolink(node_gpus[i], TOPO_IOLINK_TYPE_PCIE, i & 1);
		node_add_iolink(node_cpus[i & 1], TOPO_IOLINK_TYPE_PCIE, i + 2);
	}
	for (int i = 0; i < 4; i++) {
		for (int j = 1; j < 4; j++)
			node_add_iolink(node_gpus[i], TOPO_IOLINK_TYPE_XGMI, ((i + j) % 4) + 2);
		for (int j = 6; j < 8; j++)
			node_add_iolink(node_gpus[i], TOPO_IOLINK_TYPE_PCIE, j);
	}

	for (int i = 4; i < 8; i++) {
		node_gpus[i] = sys_add_node(&tp_src, i + 2, 0xA010 + i);
		node_gpus[i]->device_id = 0xD001;

		node_add_iolink(node_gpus[i], TOPO_IOLINK_TYPE_PCIE, i & 1);
		if (i < 6)
			node_add_iolink(node_cpus[i & 1], TOPO_IOLINK_TYPE_PCIE, i + 2);
	}
	for (int i = 4; i < 8; i++) {
		for (int j = 1; j < 4; j++)
			node_add_iolink(node_gpus[i], TOPO_IOLINK_TYPE_XGMI, ((i + j) % 4) + 6);
		for (int j = 2; j < 6; j++)
			node_add_iolink(node_gpus[i], TOPO_IOLINK_TYPE_PCIE, j);
	}

	/* Fill dest struct */
	topology_init(&tp_dest);
	tp_dest.parsed = true;

	node_cpus[0] = sys_add_node(&tp_dest, 0, 0);
	node_cpus[0]->cpu_cores_count = 1;
	node_cpus[1] = sys_add_node(&tp_dest, 1, 0);
	node_cpus[1]->cpu_cores_count = 1;

	for (int i = 0; i < 4; i++) {
		node_gpus[i] = sys_add_node(&tp_dest, i + 2, 0xB000 + i);
		node_gpus[i]->device_id = 0xD001;
		node_add_iolink(node_gpus[i], TOPO_IOLINK_TYPE_PCIE, i & 1);
		node_add_iolink(node_cpus[i & 1], TOPO_IOLINK_TYPE_PCIE, i + 2);
	}
	for (int i = 0; i < 4; i++) {
		for (int j = 1; j < 4; j++)
			node_add_iolink(node_gpus[i], TOPO_IOLINK_TYPE_XGMI, ((i + j) % 4) + 2);
		for (int j = 6; j < 8; j++)
			node_add_iolink(node_gpus[i], TOPO_IOLINK_TYPE_PCIE, j);
	}

	for (int i = 4; i < 8; i++) {
		node_gpus[i] = sys_add_node(&tp_dest, i + 2, 0xB010 + i);
		node_gpus[i]->device_id = 0xD000;

		node_add_iolink(node_gpus[i], TOPO_IOLINK_TYPE_PCIE, i & 1);
		if (i < 6)
			node_add_iolink(node_cpus[i & 1], TOPO_IOLINK_TYPE_PCIE, i + 2);
	}
	for (int i = 4; i < 8; i++) {
		for (int j = 1; j < 4; j++)
			node_add_iolink(node_gpus[i], TOPO_IOLINK_TYPE_XGMI, ((i + j) % 4) + 6);
		for (int j = 2; j < 6; j++)
			node_add_iolink(node_gpus[i], TOPO_IOLINK_TYPE_PCIE, j);
	}

	ret = set_restore_gpu_maps(&tp_src, &tp_dest, &maps);
	if (!ret) {
		if (verify_maps(&maps, ARRAY_SIZE(node_cpus), ARRAY_SIZE(node_gpus))) {
			pr_err("Mapping returned success, but results had errors\n");
			ret = -1;
		}
	}
	topology_free(&tp_src);
	topology_free(&tp_dest);
	maps_free(&maps);
	return ret;
}

int test_3(void)
{
	int ret = 0;
	struct device_maps maps;

	struct tp_node *node_gpus[8];
	struct tp_node *node_cpus[2];

	struct tp_system tp_src = { 0 };
	struct tp_system tp_dest = { 0 };

	/* Fill src struct */
	topology_init(&tp_src);
	tp_src.parsed = true;

	node_cpus[0] = sys_add_node(&tp_src, 0, 0);
	node_cpus[0]->cpu_cores_count = 1;
	node_cpus[1] = sys_add_node(&tp_src, 1, 0);
	node_cpus[1]->cpu_cores_count = 1;

	for (int i = 0; i < 4; i++) {
		node_gpus[i] = sys_add_node(&tp_src, i + 2, 0xA000 + i);
		node_gpus[i]->device_id = 0xD000;
		node_add_iolink(node_gpus[i], TOPO_IOLINK_TYPE_PCIE, i & 1);
	}
	for (int i = 0; i < 4; i++) {
		for (int j = 1; j < 4; j++)
			node_add_iolink(node_gpus[i], TOPO_IOLINK_TYPE_XGMI, ((i + j) % 4) + 2);
	}

	for (int i = 4; i < 8; i++) {
		node_gpus[i] = sys_add_node(&tp_src, i + 2, 0xA010 + i);
		node_gpus[i]->device_id = 0xD001;
		node_add_iolink(node_gpus[i], TOPO_IOLINK_TYPE_PCIE, i & 1);
	}
	for (int i = 4; i < 8; i++) {
		for (int j = 1; j < 4; j++)
			node_add_iolink(node_gpus[i], TOPO_IOLINK_TYPE_XGMI, ((i + j) % 4) + 6);
	}

	node_add_iolink(node_cpus[0], TOPO_IOLINK_TYPE_PCIE, 4);
	node_add_iolink(node_cpus[1], TOPO_IOLINK_TYPE_PCIE, 9);

	/* Fill dest struct */
	topology_init(&tp_dest);
	tp_dest.parsed = true;

	node_cpus[0] = sys_add_node(&tp_dest, 0, 0);
	node_cpus[0]->cpu_cores_count = 1;
	node_cpus[1] = sys_add_node(&tp_dest, 1, 0);
	node_cpus[1]->cpu_cores_count = 1;

	for (int i = 0; i < 4; i++) {
		node_gpus[i] = sys_add_node(&tp_dest, i + 2, 0xB000 + i);
		node_gpus[i]->device_id = 0xD000;
		node_add_iolink(node_gpus[i], TOPO_IOLINK_TYPE_PCIE, i & 1);
	}
	for (int i = 0; i < 4; i++) {
		for (int j = 1; j < 4; j++)
			node_add_iolink(node_gpus[i], TOPO_IOLINK_TYPE_XGMI, ((i + j) % 4) + 2);
	}

	for (int i = 4; i < 8; i++) {
		node_gpus[i] = sys_add_node(&tp_dest, i + 2, 0xB010 + i);
		node_gpus[i]->device_id = 0xD001;
		node_add_iolink(node_gpus[i], TOPO_IOLINK_TYPE_PCIE, i & 1);
	}
	for (int i = 4; i < 8; i++) {
		for (int j = 1; j < 4; j++)
			node_add_iolink(node_gpus[i], TOPO_IOLINK_TYPE_XGMI, ((i + j) % 4) + 6);
	}

	node_add_iolink(node_cpus[0], TOPO_IOLINK_TYPE_PCIE, 2);
	node_add_iolink(node_cpus[1], TOPO_IOLINK_TYPE_PCIE, 7);

	ret = set_restore_gpu_maps(&tp_src, &tp_dest, &maps);
	if (!ret) {
		if (verify_maps(&maps, ARRAY_SIZE(node_cpus), ARRAY_SIZE(node_gpus))) {
			pr_err("Mapping returned success, but results had errors\n");
			ret = -1;
		}
	}
	topology_free(&tp_src);
	topology_free(&tp_dest);
	maps_free(&maps);
	return ret;
}

int test_4(void)
{
	int ret = 0;
	struct device_maps maps;

	struct tp_node *node_gpus[8];
	struct tp_node *node_cpus[2];

	struct tp_system tp_src = { 0 };
	struct tp_system tp_dest = { 0 };

	/* Fill src struct */
	topology_init(&tp_src);
	tp_src.parsed = true;

	node_cpus[0] = sys_add_node(&tp_src, 0, 0);
	node_cpus[0]->cpu_cores_count = 1;
	node_cpus[1] = sys_add_node(&tp_src, 1, 0);
	node_cpus[1]->cpu_cores_count = 1;

	for (int i = 0; i < 4; i++) {
		node_gpus[i] = sys_add_node(&tp_src, i + 2, 0xA000 + i);
		node_gpus[i]->device_id = 0xD000;
		node_add_iolink(node_gpus[i], TOPO_IOLINK_TYPE_PCIE, i & 1);
	}
	for (int i = 0; i < 4; i++) {
		for (int j = 1; j < 4; j++)
			node_add_iolink(node_gpus[i], TOPO_IOLINK_TYPE_XGMI, ((i + j) % 4) + 2);
	}

	for (int i = 4; i < 8; i++) {
		node_gpus[i] = sys_add_node(&tp_src, i + 2, 0xA010 + i);
		node_gpus[i]->device_id = 0xD001;
		node_add_iolink(node_gpus[i], TOPO_IOLINK_TYPE_PCIE, i & 1);
	}
	for (int i = 4; i < 8; i++) {
		for (int j = 1; j < 4; j++)
			node_add_iolink(node_gpus[i], TOPO_IOLINK_TYPE_XGMI, ((i + j) % 4) + 6);
	}

	node_add_iolink(node_cpus[0], TOPO_IOLINK_TYPE_PCIE, 4);
	node_add_iolink(node_cpus[1], TOPO_IOLINK_TYPE_PCIE, 9);

	/* Fill dest struct */
	topology_init(&tp_dest);
	tp_dest.parsed = true;

	node_cpus[0] = sys_add_node(&tp_dest, 0, 0);
	node_cpus[0]->cpu_cores_count = 1;
	node_cpus[1] = sys_add_node(&tp_dest, 1, 0);
	node_cpus[1]->cpu_cores_count = 1;

	for (int i = 0; i < 4; i++) {
		node_gpus[i] = sys_add_node(&tp_dest, i + 2, 0xB000 + i);
		node_gpus[i]->device_id = 0xD000;
		node_add_iolink(node_gpus[i], TOPO_IOLINK_TYPE_PCIE, i & 1);
	}
	for (int i = 0; i < 4; i++) {
		for (int j = 1; j < 4; j++)
			node_add_iolink(node_gpus[i], TOPO_IOLINK_TYPE_XGMI, ((i + j) % 4) + 2);
	}

	for (int i = 4; i < 8; i++) {
		node_gpus[i] = sys_add_node(&tp_dest, i + 2, 0xB010 + i);
		node_gpus[i]->device_id = 0xD001;
		node_add_iolink(node_gpus[i], TOPO_IOLINK_TYPE_PCIE, i & 1);
	}
	for (int i = 4; i < 8; i++) {
		for (int j = 1; j < 4; j++)
			node_add_iolink(node_gpus[i], TOPO_IOLINK_TYPE_XGMI, ((i + j) % 4) + 6);
	}

	node_add_iolink(node_cpus[0], TOPO_IOLINK_TYPE_PCIE, 2);
	node_add_iolink(node_cpus[1], TOPO_IOLINK_TYPE_PCIE, 6);

	ret = set_restore_gpu_maps(&tp_src, &tp_dest, &maps);
	if (!ret) {
		if (verify_maps(&maps, ARRAY_SIZE(node_cpus), ARRAY_SIZE(node_gpus))) {
			pr_err("Mapping returned success, but results had errors\n");
			ret = -1;
		}
	}
	topology_free(&tp_src);
	topology_free(&tp_dest);
	maps_free(&maps);
	return ret;
}

int test_5(void)
{
	int ret = 0;
	struct device_maps maps;

	struct tp_node *node_gpus[8];
	struct tp_node *node_cpus[2];

	struct tp_system tp_src = { 0 };
	struct tp_system tp_dest = { 0 };

	/* Fill src struct */
	topology_init(&tp_src);
	tp_src.parsed = true;

	node_cpus[0] = sys_add_node(&tp_src, 0, 0);
	node_cpus[0]->cpu_cores_count = 1;
	node_cpus[1] = sys_add_node(&tp_src, 1, 0);
	node_cpus[1]->cpu_cores_count = 1;

	for (int i = 0; i < 4; i++) {
		node_gpus[i] = sys_add_node(&tp_src, i + 2, 0xA000 + i);
		node_gpus[i]->device_id = 0xD000;
		node_add_iolink(node_gpus[i], TOPO_IOLINK_TYPE_PCIE, i & 1);
		node_add_iolink(node_cpus[i & 1], TOPO_IOLINK_TYPE_PCIE, i + 2);
	}
	for (int i = 0; i < 4; i++) {
		for (int j = 1; j < 4; j++)
			node_add_iolink(node_gpus[i], TOPO_IOLINK_TYPE_XGMI, ((i + j) % 4) + 2);
		for (int j = 6; j < 10; j++)
			node_add_iolink(node_gpus[i], TOPO_IOLINK_TYPE_PCIE, j);
	}

	for (int i = 4; i < 8; i++) {
		node_gpus[i] = sys_add_node(&tp_src, i + 2, 0xA010 + i);
		node_gpus[i]->device_id = 0xD000;
		node_add_iolink(node_gpus[i], TOPO_IOLINK_TYPE_PCIE, i & 1);
		node_add_iolink(node_cpus[i & 1], TOPO_IOLINK_TYPE_PCIE, i + 2);
	}
	for (int i = 4; i < 8; i++) {
		for (int j = 1; j < 4; j++)
			node_add_iolink(node_gpus[i], TOPO_IOLINK_TYPE_PCIE, ((i + j) % 4) + 6);
		for (int j = 2; j < 6; j++)
			node_add_iolink(node_gpus[i], TOPO_IOLINK_TYPE_PCIE, j);
	}

	/* Fill dest struct */
	topology_init(&tp_dest);
	tp_dest.parsed = true;

	node_cpus[0] = sys_add_node(&tp_dest, 0, 0);
	node_cpus[0]->cpu_cores_count = 1;
	node_cpus[1] = sys_add_node(&tp_dest, 1, 0);
	node_cpus[1]->cpu_cores_count = 1;

	for (int i = 0; i < 4; i++) {
		node_gpus[i] = sys_add_node(&tp_dest, i + 2, 0xB000 + i);
		node_gpus[i]->device_id = 0xD000;
		node_add_iolink(node_gpus[i], TOPO_IOLINK_TYPE_PCIE, i & 1);
		node_add_iolink(node_cpus[i & 1], TOPO_IOLINK_TYPE_PCIE, i + 2);
	}
	for (int i = 0; i < 4; i++) {
		for (int j = 1; j < 4; j++)
			node_add_iolink(node_gpus[i], TOPO_IOLINK_TYPE_XGMI, ((i + j) % 4) + 2);
		for (int j = 6; j < 10; j++)
			node_add_iolink(node_gpus[i], TOPO_IOLINK_TYPE_PCIE, j);
	}

	for (int i = 4; i < 8; i++) {
		node_gpus[i] = sys_add_node(&tp_dest, i + 2, 0xB010 + i);
		node_gpus[i]->device_id = 0xD000;
		node_add_iolink(node_gpus[i], TOPO_IOLINK_TYPE_PCIE, i & 1);
		node_add_iolink(node_cpus[i & 1], TOPO_IOLINK_TYPE_PCIE, i + 2);
	}
	for (int i = 4; i < 8; i++) {
		for (int j = 1; j < 4; j++)
			node_add_iolink(node_gpus[i], TOPO_IOLINK_TYPE_PCIE, ((i + j) % 4) + 6);
		for (int j = 2; j < 6; j++)
			node_add_iolink(node_gpus[i], TOPO_IOLINK_TYPE_PCIE, j);
	}

	ret = set_restore_gpu_maps(&tp_src, &tp_dest, &maps);
	if (!ret) {
		if (verify_maps(&maps, ARRAY_SIZE(node_cpus), ARRAY_SIZE(node_gpus))) {
			pr_err("Mapping returned success, but results had errors\n");
			ret = -1;
		}
	}
	topology_free(&tp_src);
	topology_free(&tp_dest);
	maps_free(&maps);
	return ret;
}

int test_6(void)
{
	int ret = 0;
	struct device_maps maps;

	struct tp_node *node_gpus[5];
	struct tp_node *node_cpus[1];

	struct tp_system tp_src = { 0 };
	struct tp_system tp_dest = { 0 };

	/* Fill src struct */
	topology_init(&tp_src);
	tp_src.parsed = true;

	node_cpus[0] = sys_add_node(&tp_src, 0, 0);
	node_cpus[0]->cpu_cores_count = 1;

	for (int i = 0; i < 5; i++) {
		node_gpus[i] = sys_add_node(&tp_src, i + 1, 0xA000 + i);
		node_add_iolink(node_gpus[i], TOPO_IOLINK_TYPE_PCIE, 0);
		node_add_iolink(node_cpus[0], TOPO_IOLINK_TYPE_PCIE, i + 1);
	}
	node_gpus[0]->device_id = 0xD000;
	node_gpus[1]->device_id = 0xD000;
	node_gpus[2]->device_id = 0xD001;
	node_gpus[3]->device_id = 0xD000;
	node_gpus[4]->device_id = 0xD001;

	node_add_iolink(node_gpus[0], TOPO_IOLINK_TYPE_PCIE, 2);
	node_add_iolink(node_gpus[0], TOPO_IOLINK_TYPE_PCIE, 3);
	node_add_iolink(node_gpus[0], TOPO_IOLINK_TYPE_PCIE, 4);

	node_add_iolink(node_gpus[1], TOPO_IOLINK_TYPE_PCIE, 1);
	node_add_iolink(node_gpus[1], TOPO_IOLINK_TYPE_PCIE, 3);
	node_add_iolink(node_gpus[1], TOPO_IOLINK_TYPE_PCIE, 4);

	node_add_iolink(node_gpus[2], TOPO_IOLINK_TYPE_PCIE, 1);
	node_add_iolink(node_gpus[2], TOPO_IOLINK_TYPE_PCIE, 2);
	node_add_iolink(node_gpus[2], TOPO_IOLINK_TYPE_PCIE, 4);

	node_add_iolink(node_gpus[3], TOPO_IOLINK_TYPE_PCIE, 1);
	node_add_iolink(node_gpus[3], TOPO_IOLINK_TYPE_PCIE, 2);
	node_add_iolink(node_gpus[3], TOPO_IOLINK_TYPE_PCIE, 3);

	node_add_iolink(node_gpus[4], TOPO_IOLINK_TYPE_PCIE, 1);
	node_add_iolink(node_gpus[4], TOPO_IOLINK_TYPE_PCIE, 2);
	node_add_iolink(node_gpus[4], TOPO_IOLINK_TYPE_PCIE, 3);
	node_add_iolink(node_gpus[4], TOPO_IOLINK_TYPE_PCIE, 4);

	/* Fill dest struct */
	topology_init(&tp_dest);
	tp_dest.parsed = true;

	node_cpus[0] = sys_add_node(&tp_dest, 0, 0);
	node_cpus[0]->cpu_cores_count = 1;

	for (int i = 0; i < 5; i++) {
		node_gpus[i] = sys_add_node(&tp_dest, i + 1, 0xB000 + i);
		node_add_iolink(node_gpus[i], TOPO_IOLINK_TYPE_PCIE, 0);
		node_add_iolink(node_cpus[0], TOPO_IOLINK_TYPE_PCIE, i + 1);
	}
	node_gpus[0]->device_id = 0xD000;
	node_gpus[1]->device_id = 0xD001;
	node_gpus[2]->device_id = 0xD000;
	node_gpus[3]->device_id = 0xD000;
	node_gpus[4]->device_id = 0xD001;

	node_add_iolink(node_gpus[0], TOPO_IOLINK_TYPE_PCIE, 2);
	node_add_iolink(node_gpus[0], TOPO_IOLINK_TYPE_PCIE, 3);
	node_add_iolink(node_gpus[0], TOPO_IOLINK_TYPE_PCIE, 4);

	node_add_iolink(node_gpus[1], TOPO_IOLINK_TYPE_PCIE, 1);
	node_add_iolink(node_gpus[1], TOPO_IOLINK_TYPE_PCIE, 3);
	node_add_iolink(node_gpus[1], TOPO_IOLINK_TYPE_PCIE, 4);

	node_add_iolink(node_gpus[2], TOPO_IOLINK_TYPE_PCIE, 1);
	node_add_iolink(node_gpus[2], TOPO_IOLINK_TYPE_PCIE, 2);
	node_add_iolink(node_gpus[2], TOPO_IOLINK_TYPE_PCIE, 4);

	node_add_iolink(node_gpus[3], TOPO_IOLINK_TYPE_PCIE, 1);
	node_add_iolink(node_gpus[3], TOPO_IOLINK_TYPE_PCIE, 2);
	node_add_iolink(node_gpus[3], TOPO_IOLINK_TYPE_PCIE, 3);

	node_add_iolink(node_gpus[4], TOPO_IOLINK_TYPE_PCIE, 1);
	node_add_iolink(node_gpus[4], TOPO_IOLINK_TYPE_PCIE, 2);
	node_add_iolink(node_gpus[4], TOPO_IOLINK_TYPE_PCIE, 3);
	node_add_iolink(node_gpus[4], TOPO_IOLINK_TYPE_PCIE, 4);

	ret = set_restore_gpu_maps(&tp_src, &tp_dest, &maps);
	if (!ret) {
		if (verify_maps(&maps, ARRAY_SIZE(node_cpus), ARRAY_SIZE(node_gpus))) {
			pr_err("Mapping returned success, but results had errors\n");
			ret = -1;
		}
	}
	topology_free(&tp_src);
	topology_free(&tp_dest);
	maps_free(&maps);
	return ret;
}

int test_7(void)
{
	int ret = 0;
	struct device_maps maps;

	struct tp_node *node_gpus[8];
	struct tp_node *node_cpus[2];

	struct tp_system tp_src = { 0 };
	struct tp_system tp_dest = { 0 };

	/* Fill src struct */
	topology_init(&tp_src);
	tp_src.parsed = true;

	node_cpus[0] = sys_add_node(&tp_src, 0, 0);
	node_cpus[0]->cpu_cores_count = 1;
	node_cpus[1] = sys_add_node(&tp_src, 1, 0);
	node_cpus[1]->cpu_cores_count = 1;

	for (int i = 0; i < 4; i++) {
		node_gpus[i] = sys_add_node(&tp_src, i + 2, 0xA000 + i);
		node_gpus[i]->device_id = 0xD000;
		node_add_iolink(node_gpus[i], TOPO_IOLINK_TYPE_PCIE, i & 1);
	}
	for (int i = 0; i < 4; i++) {
		for (int j = 1; j < 4; j++)
			node_add_iolink(node_gpus[i], TOPO_IOLINK_TYPE_XGMI, ((i + j) % 4) + 2);
	}

	for (int i = 4; i < 8; i++) {
		node_gpus[i] = sys_add_node(&tp_src, i + 2, 0xA010 + i);
		node_gpus[i]->device_id = 0xD000;
	}

	/* Fill dest struct */
	topology_init(&tp_dest);
	tp_dest.parsed = true;

	node_cpus[0] = sys_add_node(&tp_dest, 0, 0);
	node_cpus[0]->cpu_cores_count = 1;
	node_cpus[1] = sys_add_node(&tp_dest, 1, 0);
	node_cpus[1]->cpu_cores_count = 1;

	for (int i = 0; i < 4; i++) {
		node_gpus[i] = sys_add_node(&tp_dest, i + 2, 0xB000 + i);
		node_gpus[i]->device_id = 0xD000;
		node_add_iolink(node_gpus[i], TOPO_IOLINK_TYPE_PCIE, i & 1);
	}
	for (int i = 0; i < 4; i++) {
		for (int j = 1; j < 4; j++)
			node_add_iolink(node_gpus[i], TOPO_IOLINK_TYPE_XGMI, ((i + j) % 4) + 2);
	}

	for (int i = 4; i < 8; i++) {
		node_gpus[i] = sys_add_node(&tp_dest, i + 2, 0xB010 + i);
		node_gpus[i]->device_id = 0xD000;
	}
	for (int i = 4; i < 8; i++) {
		for (int j = 1; j < 4; j++)
			node_add_iolink(node_gpus[i], TOPO_IOLINK_TYPE_XGMI, ((i + j) % 4) + 6);
	}

	ret = set_restore_gpu_maps(&tp_src, &tp_dest, &maps);

	if (!ret) {
		if (verify_maps(&maps, ARRAY_SIZE(node_cpus), ARRAY_SIZE(node_gpus))) {
			pr_err("Mapping returned success, but results had errors\n");
			ret = -1;
		}
	}
	topology_free(&tp_src);
	topology_free(&tp_dest);
	maps_free(&maps);
	return ret;
}

int test_8(void)
{
	int ret = 0;
	struct device_maps maps;

	struct tp_node *node_gpus[5];
	struct tp_node *node_cpus[1];

	struct tp_system tp_src = { 0 };
	struct tp_system tp_dest = { 0 };

	/* Fill src struct */
	topology_init(&tp_src);
	tp_src.parsed = true;

	node_cpus[0] = sys_add_node(&tp_src, 0, 0);
	node_cpus[0]->cpu_cores_count = 1;

	for (int i = 0; i < 5; i++) {
		node_gpus[i] = sys_add_node(&tp_src, i + 1, 0xA000 + i);
		node_gpus[i]->device_id = 0xD000;
		node_add_iolink(node_gpus[i], TOPO_IOLINK_TYPE_PCIE, 0);
		node_add_iolink(node_cpus[0], TOPO_IOLINK_TYPE_PCIE, i + 1);
	}

	node_add_iolink(node_gpus[0], TOPO_IOLINK_TYPE_PCIE, 2);
	node_add_iolink(node_gpus[0], TOPO_IOLINK_TYPE_PCIE, 3);

	node_add_iolink(node_gpus[1], TOPO_IOLINK_TYPE_PCIE, 1);
	node_add_iolink(node_gpus[1], TOPO_IOLINK_TYPE_PCIE, 3);

	node_add_iolink(node_gpus[2], TOPO_IOLINK_TYPE_PCIE, 1);
	node_add_iolink(node_gpus[2], TOPO_IOLINK_TYPE_PCIE, 2);

	node_add_iolink(node_gpus[3], TOPO_IOLINK_TYPE_PCIE, 1);
	node_add_iolink(node_gpus[3], TOPO_IOLINK_TYPE_PCIE, 2);
	node_add_iolink(node_gpus[3], TOPO_IOLINK_TYPE_PCIE, 3);

	node_add_iolink(node_gpus[4], TOPO_IOLINK_TYPE_PCIE, 1);
	node_add_iolink(node_gpus[4], TOPO_IOLINK_TYPE_PCIE, 2);
	node_add_iolink(node_gpus[4], TOPO_IOLINK_TYPE_PCIE, 3);

	/* Fill dest struct */
	topology_init(&tp_dest);
	tp_dest.parsed = true;

	node_cpus[0] = sys_add_node(&tp_dest, 0, 0);
	node_cpus[0]->cpu_cores_count = 1;

	for (int i = 0; i < 5; i++) {
		node_gpus[i] = sys_add_node(&tp_dest, i + 1, 0xB000 + i);
		node_gpus[i]->device_id = 0xD000;
		node_add_iolink(node_gpus[i], TOPO_IOLINK_TYPE_PCIE, 0);
		node_add_iolink(node_cpus[0], TOPO_IOLINK_TYPE_PCIE, i + 1);
	}

	node_add_iolink(node_gpus[0], TOPO_IOLINK_TYPE_PCIE, 2);
	node_add_iolink(node_gpus[0], TOPO_IOLINK_TYPE_PCIE, 3);
	node_add_iolink(node_gpus[0], TOPO_IOLINK_TYPE_PCIE, 4);

	node_add_iolink(node_gpus[1], TOPO_IOLINK_TYPE_PCIE, 1);
	node_add_iolink(node_gpus[1], TOPO_IOLINK_TYPE_PCIE, 3);
	node_add_iolink(node_gpus[1], TOPO_IOLINK_TYPE_PCIE, 4);

	node_add_iolink(node_gpus[2], TOPO_IOLINK_TYPE_PCIE, 1);
	node_add_iolink(node_gpus[2], TOPO_IOLINK_TYPE_PCIE, 2);
	node_add_iolink(node_gpus[2], TOPO_IOLINK_TYPE_PCIE, 4);

	node_add_iolink(node_gpus[3], TOPO_IOLINK_TYPE_PCIE, 1);
	node_add_iolink(node_gpus[3], TOPO_IOLINK_TYPE_PCIE, 2);
	node_add_iolink(node_gpus[3], TOPO_IOLINK_TYPE_PCIE, 3);

	node_add_iolink(node_gpus[4], TOPO_IOLINK_TYPE_PCIE, 1);
	node_add_iolink(node_gpus[4], TOPO_IOLINK_TYPE_PCIE, 2);
	node_add_iolink(node_gpus[4], TOPO_IOLINK_TYPE_PCIE, 3);
	node_add_iolink(node_gpus[4], TOPO_IOLINK_TYPE_PCIE, 4);

	ret = set_restore_gpu_maps(&tp_src, &tp_dest, &maps);

	if (!ret) {
		if (verify_maps(&maps, ARRAY_SIZE(node_cpus), ARRAY_SIZE(node_gpus))) {
			pr_err("Mapping returned success, but results had errors\n");
			ret = -1;
		}
	}
	topology_free(&tp_src);
	topology_free(&tp_dest);
	maps_free(&maps);
	return ret;
}

struct test {
	int (*test_func)(void);
	bool success; /* true if we expect function to return 0 */
};

int main(int argc, char **argv)
{
	int ret;
	int result = 0;

	struct test tests[] = {
		{ test_0, true }, { test_1, true }, { test_2, false }, { test_3, true }, { test_4, false },
		{ test_5, true }, { test_6, true }, { test_7, true },  { test_8, true },
	};

	if (argc > 1) {
		int run;

		if (sscanf(argv[1], "%d", &run) != 1 || (run >= ARRAY_SIZE(tests))) {
			pr_err("Usage: test_topology_remap [test_number]\n");
			pr_err("       Test number range:0-%ld\n", ARRAY_SIZE(tests) - 1);
			pr_err("       Return codes:\n");
			pr_err("         0 All tests pass\n");
			pr_err("         1 At least one test failed\n");
			pr_err("         2 Invalid parameters\n");
			return 2;
		}
		pr_info("======================================================================\n");
		pr_info("Starting test %d\n", run);
		ret = tests[run].test_func();
		pr_info("\n\nTest %d: %s\n", run, (!ret == tests[run].success) ? "PASS" : "FAILED");
		pr_info("======================================================================\n");
		return (!ret == tests[run].success) ? 0 : 1;
	}

	for (int i = 0; i < ARRAY_SIZE(tests); i++) {
		pr_info("======================================================================\n");
		pr_info("Starting test %d\n", i);
		ret = tests[i].test_func();
		pr_info("\n\nTest %d: %s\n", i, (!ret == tests[i].success) ? "PASS" : "FAILED");
		pr_info("======================================================================\n");
		if (!ret != tests[i].success)
			result = 1;
	}
	return result;
}
