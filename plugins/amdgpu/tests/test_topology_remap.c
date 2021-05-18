/**************************************************************************************************
 * GPU groups remapping unit tests
 *
 * Test cases for GPU topology group remapping when there are P2P iolinks between the GPUs. GPUs are
 * considered to be grouped when they have a P2P iolink.
 * 	a. P2P-XGMI: They are connected through a XGMI bridge
 * 	b. P2P-PCIe: They have large BAR enabled and each GPU can address full address space of the
 *         other GPU (44-bits address limitation)
 *
 * When GPUs have large BAR, but each GPU cannot address full address of each other, they do not
 * have P2P-PCIe links and are not considered for GPU grouping. The GPU still has to be remapped to
 * a GPU with large BAR on restore.
 *
 * GPUs can be part of 2 groups at the same time, i.e have P2P-XGMI links with one set of GPUs and
 * have P2P-PCIe links with another set of GPUs.
 *
 *
 * Test 0: 8 GPUs in 2 XGMI hives (full P2P-PCIe)
 *	2 XGMI hives of 4 GPUs
 *      Each hives have different type of GPU's
 *	All 8 GPUs have P2P-PCIe links
 *      2 CPU's - each cpu can access alternate GPU's
 *      EXPECT: SUCCESS
 *
 * Test 1: 8 GPUs in 2 XGMI hives (partial P2P-PCIe case 1)
 *	2 XGMI hives of 4 GPUs
 *      Last 2 GPUs do not have Large BAR, i.e
 *	6 GPUs have P2P-PCIe links and P2P-XGMI links
 *	2 GPUs only have P2P-XGMI links
 *	4 GPUs with P2P-PCIe link in first XGMI hive, 2 GPUs in the second XGMI hive
 *      EXPECT: SUCCESS
 *
 * Test 2: 8 GPUs in 2 XGMI hives (partial P2P-PCIe case 1)
 *	Same as test 2 but each hive have different device_id's so it is not possible to swap
 *      hives 1 and 2 on restore.
 *      EXPECT: FAIL
 *
 * Test 3:8 GPU's in 2 XGMI hives (partial P2P-PCIe case 2)
 *	2 XGMI hives of 4 GPUs
 *      6 GPUs do not have Large BAR, i.e
 *	Only 2 GPU's have P2P PCIe links
 * 	Both GPUs with P2P-PCIe links are in different XGMI hives but at different index between
 *      checkpointed and restored nodes
 *      Only possible way to map is to map A002 -> B0000 and A017 -> B015
 *      EXPECT: SUCCESS
 *
 * Test 4:8 GPU's in 2 XGMI hives (partial P2P-PCIe case 2)
 *	Same as 3 but not possible to map because of CPU iolink changed
 *      EXPECT: FAIL
 *
 * Test 5: 8 GPUs with 1 XGMI hive
 *    	4 GPUs in 1 XGMI hive, 4 GPUs have no XGMI bridge
 *    	All 8 GPUs have P2P-PCIe links
 *      EXPECT: SUCCESS
 *
 * Test 6: 5 GPUs (mix and match GPU types and partial large BAR)
 *	No XGMI bridges
 *	First 4 GPUs have P2P-PCIe links
 *      1 GPU has different device_id's at different locations
 *      EXPECT: SUCCESS
 *
 **************************************************************************************************
 * Tests where restore node has more bigger/more groups than checkpointed node
 *
 * Test 7: Checkpoint node has 8 GPUs (4 in XGMI hive, 4 without XGMI bridge)
 *      Restore node has 8 GPUs (2 XGMI hives)
 *      Restore should succeed - user application will not take advantage of 2 XGMI bridge
 *      EXPECT: SUCCESS
 *
 * Test 8: Checkpoint node has 5 GPUs (3 GPU's with P2P-PCIe links)
 *     Restore node has 5 GPUs (4 GPU's with P2P-PCIe links)
 *      EXPECT: SUCCESS
 *
 **************************************************************************************************/

#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include "common/list.h"

#include "amdgpu_plugin_topology.h"


#define pr_err(...) fprintf(stdout, "ERR:" __VA_ARGS__)
#define pr_info(...) fprintf(stdout, "INFO:" __VA_ARGS__)
#define pr_debug(...) fprintf(stdout, "DBG:" __VA_ARGS__)

int verify_maps(const struct device_maps *maps, uint32_t num_cpus, uint32_t num_gpus)
{
        struct id_map *map;

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
                for (int j = 4; j < 8; j++)
                        node_add_iolink(node_gpus[i], TOPO_IOLINK_TYPE_PCIE, ((i + j) % 4) + 6);
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
                for (int j = 4; j < 8; j++)
                        node_add_iolink(node_gpus[i], TOPO_IOLINK_TYPE_PCIE, ((i + j) % 4) + 2);
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
                for (int j = 4; j < 8; j++)
                        node_add_iolink(node_gpus[i], TOPO_IOLINK_TYPE_PCIE, ((i + j) % 4) + 6);
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
                for (int j = 4; j < 8; j++)
                        node_add_iolink(node_gpus[i], TOPO_IOLINK_TYPE_PCIE, ((i + j) % 4) + 2);
        }

        ret = set_restore_gpu_maps(&tp_src, &tp_dest, &maps);
        if (!ret) {
                if (verify_maps(&maps,
                                sizeof(node_cpus)/sizeof(node_cpus[0]),
                                sizeof(node_gpus)/sizeof(node_gpus[0]))) {

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
                for (int j = 4; j < 8; j++) {
                        if (((i + j) % 4) + 6 < 8)
                                node_add_iolink(node_gpus[i], TOPO_IOLINK_TYPE_PCIE, ((i + j) % 4) + 6);
                }
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
                for (int j = 4; j < 8; j++)
                        node_add_iolink(node_gpus[i], TOPO_IOLINK_TYPE_PCIE, ((i + j) % 4) + 2);
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
                for (int j = 4; j < 8; j++) {
                        if (((i + j) % 4) + 6 < 8)
                                node_add_iolink(node_gpus[i], TOPO_IOLINK_TYPE_PCIE, ((i + j) % 4) + 6);
                }
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
                for (int j = 4; j < 8; j++)
                        node_add_iolink(node_gpus[i], TOPO_IOLINK_TYPE_PCIE, ((i + j) % 4) + 2);
        }

        ret = set_restore_gpu_maps(&tp_src, &tp_dest, &maps);
        if (!ret) {
                if (verify_maps(&maps,
                                sizeof(node_cpus)/sizeof(node_cpus[0]),
                                sizeof(node_gpus)/sizeof(node_gpus[0]))) {

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
                for (int j = 4; j < 8; j++) {
                        if (((i + j) % 4) + 6 < 8)
                                node_add_iolink(node_gpus[i], TOPO_IOLINK_TYPE_PCIE, ((i + j) % 4) + 6);
                }
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
                for (int j = 4; j < 8; j++)
                        node_add_iolink(node_gpus[i], TOPO_IOLINK_TYPE_PCIE, ((i + j) % 4) + 2);
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
                for (int j = 4; j < 8; j++) {
                        if (((i + j) % 4) + 6 < 8)
                                node_add_iolink(node_gpus[i], TOPO_IOLINK_TYPE_PCIE, ((i + j) % 4) + 6);
                }
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
                for (int j = 4; j < 8; j++)
                        node_add_iolink(node_gpus[i], TOPO_IOLINK_TYPE_PCIE, ((i + j) % 4) + 2);
        }

        ret = set_restore_gpu_maps(&tp_src, &tp_dest, &maps);
        if (!ret) {
                if (verify_maps(&maps,
                                sizeof(node_cpus)/sizeof(node_cpus[0]),
                                sizeof(node_gpus)/sizeof(node_gpus[0]))) {

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
                if (verify_maps(&maps,
                                sizeof(node_cpus)/sizeof(node_cpus[0]),
                                sizeof(node_gpus)/sizeof(node_gpus[0]))) {

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
                if (verify_maps(&maps,
                                sizeof(node_cpus)/sizeof(node_cpus[0]),
                                sizeof(node_gpus)/sizeof(node_gpus[0]))) {

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
                for (int j = 4; j < 8; j++)
                        node_add_iolink(node_gpus[i], TOPO_IOLINK_TYPE_PCIE, ((i + j) % 4) + 6);
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
                for (int j = 4; j < 8; j++)
                        node_add_iolink(node_gpus[i], TOPO_IOLINK_TYPE_PCIE, ((i + j) % 4) + 2);
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
                for (int j = 4; j < 8; j++)
                        node_add_iolink(node_gpus[i], TOPO_IOLINK_TYPE_PCIE, ((i + j) % 4) + 6);
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
                for (int j = 4; j < 8; j++)
                        node_add_iolink(node_gpus[i], TOPO_IOLINK_TYPE_PCIE, ((i + j) % 4) + 2);
        }

        ret = set_restore_gpu_maps(&tp_src, &tp_dest, &maps);
        if (!ret) {
                if (verify_maps(&maps,
                                sizeof(node_cpus)/sizeof(node_cpus[0]),
                                sizeof(node_gpus)/sizeof(node_gpus[0]))) {

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

        for (int i = 0; i < 5; i++) {
                for (int j = 1; j < 5; j++) {
                        if (((i + j) % 5) + 1 < 5)
                                node_add_iolink(node_gpus[i], TOPO_IOLINK_TYPE_PCIE, ((i + j) % 5) + 1);
                }
        }

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

        for (int i = 0; i < 5; i++) {
                for (int j = 1; j < 5; j++) {
                        if (((i + j) % 5) + 1 < 5)
                                node_add_iolink(node_gpus[i], TOPO_IOLINK_TYPE_PCIE, ((i + j) % 5) + 1);
                }
        }

        ret = set_restore_gpu_maps(&tp_src, &tp_dest, &maps);
        if (!ret) {
                if (verify_maps(&maps,
                                sizeof(node_cpus)/sizeof(node_cpus[0]),
                                sizeof(node_gpus)/sizeof(node_gpus[0]))) {

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
                if (verify_maps(&maps,
                                sizeof(node_cpus)/sizeof(node_cpus[0]),
                                sizeof(node_gpus)/sizeof(node_gpus[0]))) {

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

        for (int i = 0; i < 5; i++) {
                for (int j = 1; j < 5; j++) {
                        if (((i + j) % 5) + 1 < 4)
                                node_add_iolink(node_gpus[i], TOPO_IOLINK_TYPE_PCIE, ((i + j) % 5) + 1);
                }
        }

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

        for (int i = 0; i < 5; i++) {
                for (int j = 1; j < 5; j++) {
                        if (((i + j) % 5) + 1 < 5)
                                node_add_iolink(node_gpus[i], TOPO_IOLINK_TYPE_PCIE, ((i + j) % 5) + 1);
                }
        }

        ret = set_restore_gpu_maps(&tp_src, &tp_dest, &maps);

        if (!ret) {
                if (verify_maps(&maps,
                                sizeof(node_cpus)/sizeof(node_cpus[0]),
                                sizeof(node_gpus)/sizeof(node_gpus[0]))) {

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

int main(int argc, char** argv)
{
        int ret;

        struct test tests[] = {
                { test_0, true },
                { test_1, true },
                { test_2, false },
                { test_3, true },
                { test_4, false },
                { test_5, true },
                { test_6, true },
                { test_7, true },
                { test_8, true },
        };

        if (argc > 1) {
                int run;
                if (sscanf(argv[1], "%d", &run) != 1 ||
                    (run >= sizeof(tests)/sizeof(tests[0]))) {
                        pr_err("Usage: test_topology_remap [test_number]\n");
                        pr_err("       Test number range:0-%ld\n", sizeof(tests)/sizeof(tests[0])-1);
                        return -EINVAL;
                }
                pr_info("===============================================================================\n");
                pr_info("Starting test %d\n", run);
                ret = tests[run].test_func();
                pr_info("\n\nTest %d: %s\n", run, (!!ret == tests[run].success) ? "FAILED" : "PASS");
                pr_info("===============================================================================\n");
                return 0;
        }

        for (int i = 0; i < sizeof(tests)/sizeof(tests[0]); i++) {
                pr_info("===============================================================================\n");
                pr_info("Starting test %d\n", i);
                ret = tests[i].test_func();
                pr_info("\n\nTest %d: %s\n", i, (!!ret == tests[i].success) ? "FAILED" : "PASS");
                pr_info("===============================================================================\n");
        }
        return 0;
}