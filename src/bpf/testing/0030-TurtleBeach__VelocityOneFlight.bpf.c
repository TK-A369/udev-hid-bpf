// Not sure about the minimum kernel version - made safe assumption

#include "hid_bpf.h"
#include "hid_bpf_helpers.h"
#include "hid_report_helpers.h"
#include "vmlinux.h"
#include <bpf/bpf_tracing.h>

#define VID_TURTLEBEACH 0x10F5
#define PID_TURTLEBEACH_VELOCITYONE_FLIGHT 0x7001

HID_BPF_CONFIG(HID_DEVICE(BUS_USB, HID_GROUP_GENERIC, VID_TURTLEBEACH,
                          PID_TURTLEBEACH_VELOCITYONE_FLIGHT));

// clang-format off
static const __u8 custom_report_descriptor_1[] = {
  UsagePage_GenericDesktop
  Usage_GD_Gamepad
  CollectionApplication(
    ReportId(0x01)

    // 20 buttons
    LogicalMinimum_i8(0)
    LogicalMaximum_i8(1)
    PhysicalMinimum_i8(0)
    PhysicalMaximum_i8(1)
    ReportSize(1)
    ReportCount(20)
    UsagePage_Button
    UsageMinimum_i8(1)
    UsageMaximum_i8(20)
    Input(Var|Abs)

    // Padding
    ReportSize(1)
    ReportCount(20)
    Input(Const|Arr|Abs)

    // Left PoV hat
    ReportSize(1)
    ReportCount(4)
    UsagePage_Button
    UsageMinimum_i8(1)
    UsageMaximum_i8(4)
    Input(Var|Abs)

    // Padding
    ReportSize(1)
    ReportCount(4)
    Input(Const|Arr|Abs)

    // Right PoV hat
    ReportSize(1)
    ReportCount(4)
    UsagePage_Button
    UsageMinimum_i8(1)
    UsageMaximum_i8(4)
    Input(Var|Abs)

    // Padding
    ReportSize(1)
    ReportCount(4)
    Input(Const|Arr|Abs)

    CollectionPhysical(
      // Roll
      UsagePage_GenericDesktop
      LogicalMinimum_i8(0)
      LogicalMaximum_i16(1023)
      PhysicalMinimum_i8(0)
      PhysicalMaximum_i16(1023)
      Usage_GD_X
      ReportSize(10)
      ReportCount(1)
      Input(Var|Abs)

      // Padding
      ReportSize(6)
      ReportCount(1)
      Input(Const|Arr|Abs)

      // Pitch
      UsagePage_GenericDesktop
      LogicalMinimum_i8(0)
      LogicalMaximum_i16(1023)
      PhysicalMinimum_i8(0)
      PhysicalMaximum_i16(1023)
      Usage_GD_Y
      ReportSize(10)
      ReportCount(1)
      Input(Var|Abs)

      // Padding
      ReportSize(6)
      ReportCount(1)
      Input(Const|Arr|Abs)

      // Yaw
      UsagePage_GenericDesktop
      LogicalMinimum_i8(0)
      LogicalMaximum_i16(1023)
      PhysicalMinimum_i8(0)
      PhysicalMaximum_i16(1023)
      Usage_GD_Z
      ReportSize(10)
      ReportCount(1)
      Input(Var|Abs)

      // Padding
      ReportSize(6)
      ReportCount(1)
      Input(Const|Arr|Abs)
    )
  )
};
// clang-format on

SEC(HID_BPF_RDESC_FIXUP)
int BPF_PROG(ifnore_button_fix_rdesc, struct hid_bpf_ctx *hctx) {
  bpf_printk("%s: fixing an rdesc for yoke", __func__);

  /*hctx->bpf_rdesc;*/

  return 0;
}
