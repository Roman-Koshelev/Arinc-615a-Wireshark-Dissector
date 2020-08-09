#include <stdio.h>

#include "config.h"

#include <epan/packet.h>

#include <epan/dissectors/packet-tftp.h>

#define PARS_RET_UINT16(proto_tree, name)                                                     \
    guint32 name;                                                                             \
    proto_tree_add_item_ret_uint(proto_tree, hf_a615a_##name, tvb, offset, 2, ENC_BIG_ENDIAN, \
                                 &name);                                                      \
    offset += 2

#define PARS_UINT16(proto_tree, name)                                                 \
    proto_tree_add_item(proto_tree, hf_a615a_##name, tvb, offset, 2, ENC_BIG_ENDIAN); \
    offset += 2

#define PARS_UINT32(proto_tree, name)                                                 \
    proto_tree_add_item(proto_tree, hf_a615a_##name, tvb, offset, 4, ENC_BIG_ENDIAN); \
    offset += 4

#define PARS_OPERATION_STATUS_CODE(proto_tree)                                               \
    do {                                                                                     \
        PARS_RET_UINT16(proto_tree, operation_status);                                       \
        col_append_fstr(                                                                     \
            pinfo->cinfo, COL_INFO, ", Status: %s",                                          \
            val_to_str(operation_status, a615a_operation_status_codes, "Unknown (0x%04x)")); \
    } while (0);

#define PARS_LOAD_RATIO(proto_tree)                                                  \
    proto_tree_add_item(proto_tree, hf_a615a_load_ratio, tvb, offset, 3, ENC_ASCII); \
    offset += 3

#define PARS_A615STRING(proto_tree, name)                                                 \
    do {                                                                                  \
        guint32 length;                                                                   \
        proto_tree_add_item_ret_uint(proto_tree, hf_a615a_length, tvb, offset, 1, ENC_NA, \
                                     &length);                                            \
        offset += 1;                                                                      \
        proto_tree_add_item(proto_tree, hf_a615a_##name, tvb, offset, length, ENC_ASCII); \
        offset += length;                                                                 \
                                                                                          \
    } while (0)

enum A615A_SUFFIX { LCI, LCL, LCS, LNA, LND, LNL, LNO, LNR, LNS, LUI, LUR, LUS };

typedef struct _string_pair {
    const char *abbreviated;
    const char *full;
} string_pair;

static string_pair a615a_file[] = {{"LCI", "Load Configuration Initialization"},
                                   {"LCL", "Load Configuration List"},
                                   {"LCS", "Load Configuration Status"},
                                   {"LNA", "Load Downloading Answer"},
                                   {"LND", "Load Downloading Media"},
                                   {"LNL", "Load Downloading List"},
                                   {"LNO", "Load Downloading Operator"},
                                   {"LNR", "Load Downloading Request"},
                                   {"LNS", "Load Downloading Status"},
                                   {"LUI", "Load Upload Initialization"},
                                   {"LUR", "Load Uploading Request"},
                                   {"LUS", "Load Uploading Status"}};

static const value_string a615a_operation_status_codes[] = {
    {0x0001, "Accepted, not yet started"},
    {0x0002, "Operation in progress"},
    {0x0003, "Operation completed without error"},
    {0x0004, "Operation in progress, details in status description"},
    {0x1000, "Operation denied, reason in status description"},
    {0x1002, "Operation not supported by the target"},
    {0x1003, "Operation aborted by target hardware, info in status description"},
    {0x1004, "Operation aborted by target on Dataloader error message"},
    {0x1005, "Operation aborted by target on operator action"},
    {0x1007, "Load of this header file has failed, details in status description"},
    {0, NULL}};

static int proto_a615a = -1;

static gint ett_a615a = -1;

static int hf_a615a_file_length = -1;
static int hf_a615a_protocol_version = -1;
static int hf_a615a_counter = -1;
static int hf_a615a_operation_status = -1;
static int hf_a615a_exception_timer = -1;
static int hf_a615a_estimated_time = -1;
static int hf_a615a_length = -1;
static int hf_a615a_status_description = -1;
static int hf_a615a_load_ratio = -1;
static int hf_a615a_file_count = -1;
static int hf_a615a_file_name = -1;
static int hf_a615a_file_description = -1;
static int hf_a615a_part_number = -1;
static int hf_a615a_number_target_hardware = -1;
static int hf_a615a_literal_name = -1;
static int hf_a615a_serial_number = -1;
static int hf_a615a_part_number_count = -1;
static int hf_a615a_ammendment = -1;
static int hf_a615a_designation = -1;
static int hf_a615a_user_data = -1;
static int hf_a615a_file_type = -1;

static void dissect_a615a_LCL(tvbuff_t *tvb, packet_info *pinfo _U_, int offset, proto_tree *root)
{
    PARS_RET_UINT16(root, number_target_hardware);

    for (unsigned i = 0; i < number_target_hardware; ++i) {
        int len = tvb_get_guint8(tvb, offset);
        char *str = tvb_format_text(tvb, offset + 1, len - 1);
        proto_tree *target_root = proto_tree_add_subtree_format(root, tvb, offset, -1, ett_a615a,
                                                                NULL, "Target %d - %s", i + 1, str);
        int begin_offset = offset;
        PARS_A615STRING(target_root, literal_name);
        PARS_A615STRING(target_root, serial_number);
        PARS_RET_UINT16(target_root, part_number_count);

        for (unsigned j = 0; j < part_number_count; ++j) {
            int len2 = tvb_get_guint8(tvb, offset);
            char *str2 = tvb_format_text(tvb, offset + 1, len2 - 1);
            proto_tree *part_root = proto_tree_add_subtree_format(
                target_root, tvb, offset, -1, ett_a615a, NULL, "Part %d - %s", j + 1, str2);

            int begin_offset2 = offset;
            PARS_A615STRING(part_root, part_number);
            PARS_A615STRING(part_root, ammendment);
            PARS_A615STRING(part_root, designation);
            proto_item_set_len(part_root, offset - begin_offset2);
        }
        proto_item_set_len(target_root, offset - begin_offset);
    }
}

static void dissect_a615a_LUS(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *root)
{
    PARS_OPERATION_STATUS_CODE(root);
    PARS_A615STRING(root, status_description);
    PARS_UINT16(root, counter);
    PARS_UINT16(root, exception_timer);
    PARS_UINT16(root, estimated_time);
    PARS_LOAD_RATIO(root);
    PARS_RET_UINT16(root, file_count);

    for (unsigned i = 0; i < file_count; ++i) {
        int len = tvb_get_guint8(tvb, offset);
        char *str = tvb_format_text(tvb, offset + 1, len - 1);
        proto_tree *part_root = proto_tree_add_subtree_format(root, tvb, offset, -1, ett_a615a,
                                                              NULL, "Header %d - %s", i + 1, str);

        int begin_offset = offset;
        PARS_A615STRING(part_root, file_name);
        PARS_A615STRING(part_root, part_number);
        PARS_LOAD_RATIO(part_root);
        PARS_UINT16(part_root, operation_status);
        PARS_A615STRING(part_root, status_description);
        proto_item_set_len(part_root, offset - begin_offset);
    }
}

static void dissect_a615a_LCS(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *root)
{
    PARS_UINT16(root, counter);
    PARS_OPERATION_STATUS_CODE(root);
    PARS_UINT16(root, exception_timer);
    PARS_UINT16(root, estimated_time);
    PARS_A615STRING(root, status_description);
}

static void dissect_a615a_LUI(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *root)
{
    PARS_OPERATION_STATUS_CODE(root);
    PARS_A615STRING(root, status_description);
}

static void dissect_a615a_LCI(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *root)
{
    PARS_OPERATION_STATUS_CODE(root);
    PARS_A615STRING(root, status_description);
}

static void dissect_a615a_LND(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *root)
{
    PARS_OPERATION_STATUS_CODE(root);
    PARS_A615STRING(root, status_description);
}

static void dissect_a615a_LNO(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *root)
{
    PARS_OPERATION_STATUS_CODE(root);
    PARS_A615STRING(root, status_description);
}

static void dissect_a615a_LUR(tvbuff_t *tvb, packet_info *pinfo _U_, int offset, proto_tree *root)
{
    PARS_RET_UINT16(root, file_count);

    for (unsigned i = 0; i < file_count; ++i) {
        int len = tvb_get_guint8(tvb, offset);
        char *str = tvb_format_text(tvb, offset + 1, len - 1);
        proto_tree *part_root = proto_tree_add_subtree_format(root, tvb, offset, -1, ett_a615a,
                                                              NULL, "Header %d - %s", i + 1, str);

        int begin_offset = offset;
        PARS_A615STRING(part_root, file_name);
        PARS_A615STRING(part_root, part_number);
        proto_item_set_len(part_root, offset - begin_offset);
    }
}

static void dissect_a615a_LNL(tvbuff_t *tvb, packet_info *pinfo _U_, int offset, proto_tree *root)
{
    PARS_RET_UINT16(root, file_count);

    for (unsigned i = 0; i < file_count; ++i) {
        int len = tvb_get_guint8(tvb, offset);
        char *str = tvb_format_text(tvb, offset + 1, len - 1);

        proto_tree *part_root = proto_tree_add_subtree_format(root, tvb, offset, -1, ett_a615a,
                                                              NULL, "Header %d - %s", i + 1, str);

        int begin_offset = offset;
        PARS_A615STRING(part_root, file_name);
        PARS_A615STRING(part_root, file_description);
        proto_item_set_len(part_root, offset - begin_offset);
    }
}

static void dissect_a615a_LNR(tvbuff_t *tvb, packet_info *pinfo _U_, int offset, proto_tree *root)
{
    PARS_RET_UINT16(root, file_count);

    for (unsigned i = 0; i < file_count; ++i) {
        int len = tvb_get_guint8(tvb, offset);
        char *str = tvb_format_text(tvb, offset + 1, len - 1);
        proto_tree *part_root = proto_tree_add_subtree_format(root, tvb, offset, -1, ett_a615a,
                                                              NULL, "Header %d - %s", i + 1, str);

        int begin_offset = offset;
        PARS_A615STRING(part_root, file_name);
        proto_item_set_len(part_root, offset - begin_offset);
    }

    PARS_A615STRING(root, user_data);
}

static void dissect_a615a_LNS(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *root)
{
    PARS_OPERATION_STATUS_CODE(root);
    PARS_A615STRING(root, status_description);
    PARS_UINT16(root, counter);
    PARS_UINT16(root, exception_timer);
    PARS_UINT16(root, estimated_time);
    PARS_LOAD_RATIO(root);
    PARS_RET_UINT16(root, file_count);

    for (unsigned i = 0; i < file_count; ++i) {
        int len = tvb_get_guint8(tvb, offset);
        char *str = tvb_format_text(tvb, offset + 1, len - 1);

        proto_tree *part_root = proto_tree_add_subtree_format(root, tvb, offset, -1, ett_a615a,
                                                              NULL, "Header %d - %s", i + 1, str);

        int begin_offset = offset;
        PARS_A615STRING(part_root, file_name);
        PARS_UINT16(part_root, operation_status);
        PARS_A615STRING(part_root, file_description);
        proto_item_set_len(part_root, offset - begin_offset);
    }
}

static void dissect_a615a_LNA(tvbuff_t *tvb, packet_info *pinfo _U_, int offset, proto_tree *root)
{
    PARS_RET_UINT16(root, file_count);

    for (unsigned i = 0; i < file_count; ++i) {
        int len = tvb_get_guint8(tvb, offset);
        char *str = tvb_format_text(tvb, offset + 1, len - 1);
        proto_tree *part_root = proto_tree_add_subtree_format(root, tvb, offset, -1, ett_a615a,
                                                              NULL, "Header %d - %s", i + 1, str);

        int begin_offset = offset;
        PARS_A615STRING(part_root, file_name);
        proto_item_set_len(part_root, offset - begin_offset);
    }
}

static void dissect_a615a_protocol_file(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                        int suffix)
{
    proto_item *ti;
    ti = proto_tree_add_item(tree, proto_a615a, tvb, 0, -1, ENC_NA);
    proto_tree *a615a_tree = proto_item_add_subtree(ti, ett_a615a);
    ti = proto_tree_add_string(a615a_tree, hf_a615a_file_type, tvb, 0, 0, a615a_file[suffix].full);
    proto_item_set_generated(ti);

    int offset = 0;
    PARS_UINT32(a615a_tree, file_length);
    proto_tree_add_item(a615a_tree, hf_a615a_protocol_version, tvb, offset, 2, ENC_ASCII);
    offset += 2;

    switch (suffix) {
        case LCI: {
            dissect_a615a_LCI(tvb, pinfo, offset, a615a_tree);
            break;
        }
        case LCL: {
            dissect_a615a_LCL(tvb, pinfo, offset, a615a_tree);
            break;
        }
        case LCS: {
            dissect_a615a_LCS(tvb, pinfo, offset, a615a_tree);
            break;
        }
        case LNA: {
            dissect_a615a_LNA(tvb, pinfo, offset, a615a_tree);
            break;
        }
        case LND: {
            dissect_a615a_LND(tvb, pinfo, offset, a615a_tree);
            break;
        }
        case LNL: {
            dissect_a615a_LNL(tvb, pinfo, offset, a615a_tree);
            break;
        }
        case LNO: {
            dissect_a615a_LNO(tvb, pinfo, offset, a615a_tree);
            break;
        }
        case LNR: {
            dissect_a615a_LNR(tvb, pinfo, offset, a615a_tree);
            break;
        }
        case LNS: {
            dissect_a615a_LNS(tvb, pinfo, offset, a615a_tree);
            break;
        }
        case LUI: {
            dissect_a615a_LUI(tvb, pinfo, offset, a615a_tree);
            break;
        }
        case LUR: {
            dissect_a615a_LUR(tvb, pinfo, offset, a615a_tree);
            break;
        }
        case LUS: {
            dissect_a615a_LUS(tvb, pinfo, offset, a615a_tree);
            break;
        }
        default: {
            DISSECTOR_ASSERT_NOT_REACHED();
            break;
        }
    }
}

static gboolean dissect_a615a_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    guint psize = tvb_captured_length(tvb);
    if (psize < 6) return FALSE;
    if ((tvb_get_ntohl(tvb, 0) != psize) || ((gchar)tvb_get_guint8(tvb, 4) != 'A')) return FALSE;

    const char *filename = ((struct tftpinfo *)data)->filename;

    for (unsigned i = 0; i < array_length(a615a_file); ++i) {
        if (g_str_has_suffix(filename, a615a_file[i].abbreviated)) {
            col_set_str(pinfo->cinfo, COL_PROTOCOL, "A615a-3");
            col_add_str(pinfo->cinfo, COL_INFO, filename);
            dissect_a615a_protocol_file(tvb, pinfo, tree, i);
            return TRUE;
        }
    }
    return FALSE;
}

void proto_register_a615a(void)
{
    static hf_register_info hf[] = {
        {&hf_a615a_file_length,
         {"File Length", "a615a.file_length", FT_UINT32, BASE_DEC, NULL, 0x0,
          "A615a Protocol File Length", HFILL}},
        {&hf_a615a_protocol_version,
         {"Protocol Version", "a615a.protocol_version", FT_STRINGZ, BASE_NONE, NULL, 0x0,
          "A615a Protocol File Version", HFILL}},
        {&hf_a615a_counter,
         {"Counter", "a615a.counter", FT_UINT16, BASE_DEC, NULL, 0x0, "A615a Protocol Counter",
          HFILL}},
        {&hf_a615a_operation_status,
         {"Status Code", "a615a.status_code", FT_UINT16, BASE_DEC,
          VALS(a615a_operation_status_codes), 0x0, NULL, HFILL}},
        {&hf_a615a_exception_timer,
         {"Exception Timer", "a615a.exception_timer", FT_UINT16, BASE_DEC, NULL, 0x0,
          "A615a Exception Timer", HFILL}},
        {&hf_a615a_estimated_time,
         {"Estimated Time", "a615a.estimated_time", FT_UINT16, BASE_DEC, NULL, 0x0,
          "A615a Estimated Time", HFILL}},
        {&hf_a615a_length,
         {"Length", "a615a.len", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_a615a_status_description,
         {"Status Description", "a615a.status", FT_STRINGZ, BASE_NONE, NULL, 0x0,
          "A615a Status Description", HFILL}},
        {&hf_a615a_load_ratio,
         {"Load Ratio", "a615a.load_ratio", FT_STRINGZ, BASE_NONE, NULL, 0x0,
          "A615a Load Operation Ratio", HFILL}},
        {&hf_a615a_file_count,
         {"File Count", "a615a.file_count", FT_UINT16, BASE_DEC, NULL, 0x0, "A615a File Count",
          HFILL}},
        {&hf_a615a_file_name,
         {"File Name", "a615a.file_name", FT_STRINGZ, BASE_NONE, NULL, 0x0, "A615a File Name",
          HFILL}},
        {&hf_a615a_file_description,
         {"File Description", "a615a.file_description", FT_STRINGZ, BASE_NONE, NULL, 0x0,
          "A615a File Description", HFILL}},
        {&hf_a615a_part_number,
         {"Part Number", "a615a.part_number", FT_STRINGZ, BASE_NONE, NULL, 0x0, "A615a Part Number",
          HFILL}},
        {&hf_a615a_number_target_hardware,
         {"Number of Target Hardware", "a615a.num_hardware", FT_UINT16, BASE_DEC, NULL, 0x0,
          "A615a Number of Target Hardware", HFILL}},
        {&hf_a615a_literal_name,
         {"Literal Name", "a615a.literal_name", FT_STRINGZ, BASE_NONE, NULL, 0x0,
          "A615a Literal Name", HFILL}},
        {&hf_a615a_serial_number,
         {"Serial Number", "a615a.serial_number", FT_STRINGZ, BASE_NONE, NULL, 0x0,
          "A615a Serial Number", HFILL}},
        {&hf_a615a_part_number_count,
         {"Part Number Count", "a615a.num_parts", FT_UINT16, BASE_DEC, NULL, 0x0,
          "A615a Part Number Count", HFILL}},
        {&hf_a615a_ammendment,
         {"Ammendment", "a615a.ammendment", FT_STRINGZ, BASE_NONE, NULL, 0x0, "A615a Ammendment",
          HFILL}},
        {&hf_a615a_designation,
         {"Designation", "a615a.designation", FT_STRINGZ, BASE_NONE, NULL, 0x0, "A615a Designation",
          HFILL}},
        {&hf_a615a_user_data,
         {"User Data", "a615a.user_data", FT_BYTES, BASE_NONE, NULL, 0x0, "User Data", HFILL}},
        {&hf_a615a_file_type,
         {"Type", "a615a.type", FT_STRINGZ, BASE_NONE, NULL, 0x0, "A615a File type", HFILL}},
    };

    static gint *ett[] = {&ett_a615a};

    proto_a615a = proto_register_protocol("Arinc 615a Protocol", "A615a-3", "a615a");
    proto_register_field_array(proto_a615a, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void proto_reg_handoff_a615a(void)
{
    heur_dissector_add("tftp", dissect_a615a_heur, "Arinc 615a Protocol", "a615a-3", proto_a615a,
                       HEURISTIC_ENABLE);
}