#include "config.h"

#include <epan/packet.h>
#include <epan/ptvcursor.h>

#include <epan/dissectors/packet-tftp.h>

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

static void dissect_a615a_LCL(ptvcursor_t *ptvc, packet_info *pinfo _U_)
{
    guint32 th_count, pn_count;
    proto_item *pi;

    pi =
        ptvcursor_add_ret_uint(ptvc, hf_a615a_number_target_hardware, 2, ENC_BIG_ENDIAN, &th_count);

    for (unsigned i = 0; i < th_count; ++i) {
        pi = ptvcursor_add(ptvc, hf_a615a_literal_name, 1, ENC_ASCII);
        ptvcursor_push_subtree(ptvc, pi, ett_a615a);
        ptvcursor_add(ptvc, hf_a615a_serial_number, 1, ENC_ASCII);
        pi = ptvcursor_add_ret_uint(ptvc, hf_a615a_part_number_count, 2, ENC_BIG_ENDIAN, &pn_count);

        for (unsigned j = 0; j < pn_count; ++j) {
            pi = ptvcursor_add(ptvc, hf_a615a_part_number, 1, ENC_ASCII);
            ptvcursor_push_subtree(ptvc, pi, ett_a615a);
            ptvcursor_add(ptvc, hf_a615a_ammendment, 1, ENC_ASCII);
            ptvcursor_add(ptvc, hf_a615a_designation, 1, ENC_ASCII);
            ptvcursor_pop_subtree(ptvc);
        }
        ptvcursor_pop_subtree(ptvc);
    }
}

static void dissect_a615a_LUS(ptvcursor_t *ptvc, packet_info *pinfo)
{
    guint32 status, file_count;
    const guint8 *ratio;
    proto_item *pi;

    ptvcursor_add_ret_uint(ptvc, hf_a615a_operation_status, 2, ENC_BIG_ENDIAN, &status);
    col_append_fstr(pinfo->cinfo, COL_INFO, ", Status: %s",
                    val_to_str(status, a615a_operation_status_codes, "Unknown (0x%04x)"));
    ptvcursor_add(ptvc, hf_a615a_status_description, 1, ENC_ASCII);
    ptvcursor_add(ptvc, hf_a615a_counter, 2, ENC_BIG_ENDIAN);
    ptvcursor_add(ptvc, hf_a615a_exception_timer, 2, ENC_BIG_ENDIAN);
    ptvcursor_add(ptvc, hf_a615a_estimated_time, 2, ENC_BIG_ENDIAN);
    ptvcursor_add_ret_string(ptvc, hf_a615a_load_ratio, 3, ENC_ASCII, wmem_packet_scope(), &ratio);
    col_append_fstr(pinfo->cinfo, COL_INFO, ", Load Ratio: %s %%", ratio);
    pi = ptvcursor_add_ret_uint(ptvc, hf_a615a_file_count, 2, ENC_BIG_ENDIAN, &file_count);

    ptvcursor_push_subtree(ptvc, pi, ett_a615a);
    for (unsigned i = 0; i < file_count; ++i) {
        pi = ptvcursor_add(ptvc, hf_a615a_file_name, 1, ENC_ASCII);
        ptvcursor_push_subtree(ptvc, pi, ett_a615a);
        ptvcursor_add(ptvc, hf_a615a_part_number, 1, ENC_ASCII);
        ptvcursor_add(ptvc, hf_a615a_load_ratio, 3, ENC_ASCII);
        ptvcursor_add(ptvc, hf_a615a_operation_status, 2, ENC_BIG_ENDIAN);
        ptvcursor_add(ptvc, hf_a615a_status_description, 1, ENC_ASCII);
        ptvcursor_pop_subtree(ptvc);
    }
    ptvcursor_pop_subtree(ptvc);
}

static void dissect_a615a_LCS(ptvcursor_t *ptvc, packet_info *pinfo)
{
    guint32 status;

    ptvcursor_add(ptvc, hf_a615a_counter, 2, ENC_BIG_ENDIAN);
    ptvcursor_add_ret_uint(ptvc, hf_a615a_operation_status, 2, ENC_BIG_ENDIAN, &status);
    col_append_fstr(pinfo->cinfo, COL_INFO, ", Status: %s",
                    val_to_str(status, a615a_operation_status_codes, "Unknown (0x%04x)"));
    ptvcursor_add(ptvc, hf_a615a_exception_timer, 2, ENC_BIG_ENDIAN);
    ptvcursor_add(ptvc, hf_a615a_estimated_time, 2, ENC_BIG_ENDIAN);
    ptvcursor_add(ptvc, hf_a615a_status_description, 1, ENC_ASCII);
}

static void dissect_a615a_LUI_LCI_LND_LNO(ptvcursor_t *ptvc, packet_info *pinfo)
{
    guint32 status;

    ptvcursor_add_ret_uint(ptvc, hf_a615a_operation_status, 2, ENC_BIG_ENDIAN, &status);
    col_append_fstr(pinfo->cinfo, COL_INFO, ", Status: %s",
                    val_to_str(status, a615a_operation_status_codes, "Unknown (0x%04x)"));
    ptvcursor_add(ptvc, hf_a615a_status_description, 1, ENC_ASCII);
}

static void dissect_a615a_LUR(ptvcursor_t *ptvc, packet_info *pinfo _U_)
{
    guint32 file_count;
    proto_item *pi;

    ptvcursor_add_ret_uint(ptvc, hf_a615a_file_count, 2, ENC_BIG_ENDIAN, &file_count);
    for (unsigned i = 0; i < file_count; ++i) {
        pi = ptvcursor_add(ptvc, hf_a615a_file_name, 1, ENC_ASCII);
        ptvcursor_push_subtree(ptvc, pi, ett_a615a);
        ptvcursor_add(ptvc, hf_a615a_part_number, 1, ENC_ASCII);
        ptvcursor_pop_subtree(ptvc);
    }
}

static void dissect_a615a_LNL(ptvcursor_t *ptvc, packet_info *pinfo _U_)
{
    guint32 file_count;
    proto_item *pi;

    ptvcursor_add_ret_uint(ptvc, hf_a615a_file_count, 2, ENC_BIG_ENDIAN, &file_count);
    for (unsigned i = 0; i < file_count; ++i) {
        pi = ptvcursor_add(ptvc, hf_a615a_file_name, 1, ENC_ASCII);
        ptvcursor_push_subtree(ptvc, pi, ett_a615a);
        ptvcursor_add(ptvc, hf_a615a_file_description, 1, ENC_ASCII);
        ptvcursor_pop_subtree(ptvc);
    }
}

static void dissect_a615a_LNR(ptvcursor_t *ptvc, packet_info *pinfo _U_)
{
    guint32 file_count;

    ptvcursor_add_ret_uint(ptvc, hf_a615a_file_count, 2, ENC_BIG_ENDIAN, &file_count);
    for (unsigned i = 0; i < file_count; ++i) {
        ptvcursor_add(ptvc, hf_a615a_file_name, 1, ENC_ASCII);
    }
    ptvcursor_add(ptvc, hf_a615a_user_data, 1, ENC_NA);
}

static void dissect_a615a_LNS(ptvcursor_t *ptvc, packet_info *pinfo)
{
    guint32 status, file_count;
    proto_item *pi;

    ptvcursor_add_ret_uint(ptvc, hf_a615a_operation_status, 2, ENC_BIG_ENDIAN, &status);
    col_append_fstr(pinfo->cinfo, COL_INFO, ", Status: %s",
                    val_to_str(status, a615a_operation_status_codes, "Unknown (0x%04x)"));
    ptvcursor_add(ptvc, hf_a615a_status_description, 1, ENC_ASCII);
    ptvcursor_add(ptvc, hf_a615a_counter, 2, ENC_BIG_ENDIAN);
    ptvcursor_add(ptvc, hf_a615a_exception_timer, 2, ENC_BIG_ENDIAN);
    ptvcursor_add(ptvc, hf_a615a_estimated_time, 2, ENC_BIG_ENDIAN);
    ptvcursor_add(ptvc, hf_a615a_load_ratio, 3, ENC_ASCII);
    ptvcursor_add_ret_uint(ptvc, hf_a615a_file_count, 2, ENC_BIG_ENDIAN, &file_count);

    for (unsigned i = 0; i < file_count; ++i) {
        pi = ptvcursor_add(ptvc, hf_a615a_file_name, 1, ENC_ASCII);
        ptvcursor_push_subtree(ptvc, pi, ett_a615a);
        ptvcursor_add(ptvc, hf_a615a_operation_status, 2, ENC_BIG_ENDIAN);
        ptvcursor_add(ptvc, hf_a615a_file_description, 1, ENC_ASCII);
        ptvcursor_pop_subtree(ptvc);
    }
}

static void dissect_a615a_LNA(ptvcursor_t *ptvc, packet_info *pinfo _U_)
{
    guint32 file_count;

    ptvcursor_add_ret_uint(ptvc, hf_a615a_file_count, 2, ENC_BIG_ENDIAN, &file_count);
    for (unsigned i = 0; i < file_count; ++i) {
        ptvcursor_add(ptvc, hf_a615a_file_name, 1, ENC_ASCII);
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

    ptvcursor_t *ptvc = ptvcursor_new(a615a_tree, tvb, 0);
    ptvcursor_add(ptvc, hf_a615a_file_length, 4, ENC_BIG_ENDIAN);
    ptvcursor_add(ptvc, hf_a615a_protocol_version, 2, ENC_ASCII);

    switch (suffix) {
        case LUI:
        case LCI:
        case LND:
        case LNO: {
            dissect_a615a_LUI_LCI_LND_LNO(ptvc, pinfo);
            break;
        }
        case LCL: {
            dissect_a615a_LCL(ptvc, pinfo);
            break;
        }
        case LCS: {
            dissect_a615a_LCS(ptvc, pinfo);
            break;
        }
        case LNA: {
            dissect_a615a_LNA(ptvc, pinfo);
            break;
        }
        case LNL: {
            dissect_a615a_LNL(ptvc, pinfo);
            break;
        }
        case LNR: {
            dissect_a615a_LNR(ptvc, pinfo);
            break;
        }
        case LNS: {
            dissect_a615a_LNS(ptvc, pinfo);
            break;
        }
        case LUR: {
            dissect_a615a_LUR(ptvc, pinfo);
            break;
        }
        case LUS: {
            dissect_a615a_LUS(ptvc, pinfo);
            break;
        }
        default: {
            DISSECTOR_ASSERT_NOT_REACHED();
            break;
        }
    }
    ptvcursor_free(ptvc);
}

static gboolean dissect_a615a_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    guint psize = tvb_captured_length(tvb);
    if (psize < 6) return FALSE;
    if ((tvb_get_ntohl(tvb, 0) != psize) || ((gchar)tvb_get_guint8(tvb, 4) != 'A')) return FALSE;

    const char *filename = ((struct tftpinfo *)data)->filename;

    for (unsigned i = 0; i < array_length(a615a_file); ++i) {
        if (g_str_has_suffix(filename, a615a_file[i].abbreviated)) {
            col_set_str(pinfo->cinfo, COL_PROTOCOL, "A615a");
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
         {"Protocol Version", "a615a.protocol_version", FT_STRING, BASE_NONE, NULL, 0x0,
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
        {&hf_a615a_status_description,
         {"Status Description", "a615a.status", FT_UINT_STRING, BASE_NONE, NULL, 0x0,
          "A615a Status Description", HFILL}},
        {&hf_a615a_load_ratio,
         {"Load Ratio", "a615a.load_ratio", FT_STRING, BASE_NONE, NULL, 0x0,
          "A615a Load Operation Ratio", HFILL}},
        {&hf_a615a_file_count,
         {"File Count", "a615a.file_count", FT_UINT16, BASE_DEC, NULL, 0x0, "A615a File Count",
          HFILL}},
        {&hf_a615a_file_name,
         {"File Name", "a615a.file_name", FT_UINT_STRING, BASE_NONE, NULL, 0x0, "A615a File Name",
          HFILL}},
        {&hf_a615a_file_description,
         {"File Description", "a615a.file_description", FT_UINT_STRING, BASE_NONE, NULL, 0x0,
          "A615a File Description", HFILL}},
        {&hf_a615a_part_number,
         {"Part Number", "a615a.part_number", FT_UINT_STRING, BASE_NONE, NULL, 0x0,
          "A615a Part Number", HFILL}},
        {&hf_a615a_number_target_hardware,
         {"Number of Target Hardware", "a615a.num_hardware", FT_UINT16, BASE_DEC, NULL, 0x0,
          "A615a Number of Target Hardware", HFILL}},
        {&hf_a615a_literal_name,
         {"Literal Name", "a615a.literal_name", FT_UINT_STRING, BASE_NONE, NULL, 0x0,
          "A615a Literal Name", HFILL}},
        {&hf_a615a_serial_number,
         {"Serial Number", "a615a.serial_number", FT_UINT_STRING, BASE_NONE, NULL, 0x0,
          "A615a Serial Number", HFILL}},
        {&hf_a615a_part_number_count,
         {"Part Number Count", "a615a.num_parts", FT_UINT16, BASE_DEC, NULL, 0x0,
          "A615a Part Number Count", HFILL}},
        {&hf_a615a_ammendment,
         {"Ammendment", "a615a.ammendment", FT_UINT_STRING, BASE_NONE, NULL, 0x0,
          "A615a Ammendment", HFILL}},
        {&hf_a615a_designation,
         {"Designation", "a615a.designation", FT_UINT_STRING, BASE_NONE, NULL, 0x0,
          "A615a Designation", HFILL}},
        {&hf_a615a_user_data,
         {"User Data", "a615a.user_data", FT_UINT_BYTES, BASE_NONE, NULL, 0x0, "User Data", HFILL}},
        {&hf_a615a_file_type,
         {"Type", "a615a.type", FT_STRINGZ, BASE_NONE, NULL, 0x0, "A615a File type", HFILL}},
    };

    static gint *ett[] = {&ett_a615a};

    proto_a615a = proto_register_protocol("Arinc 615a Protocol", "A615a", "a615a");
    proto_register_field_array(proto_a615a, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void proto_reg_handoff_a615a(void)
{
    heur_dissector_add("tftp", dissect_a615a_heur, "Arinc 615a Protocol", "a615a", proto_a615a,
                       HEURISTIC_ENABLE);
}