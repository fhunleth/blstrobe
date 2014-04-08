// The MIT License (MIT)
//
// Copyright (c) 2014 LKC Technologies, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of
// this software and associated documentation files (the "Software"), to deal in
// the Software without restriction, including without limitation the rights to
// use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software is furnished to do so,
// subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
// FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
// IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <endian.h>

#include <linux/i2c.h>
#include <linux/i2c-dev.h>
#include "config.h"

#define MAX_RETRIES     20

#define MAX_DISPLAYS    16
#define EDID_SIZE       128

#define EDID_I2C_ADDR   0x50
#define DDC_I2C_ADDR    0x37

#define DDC_OPCODE_VCP_REQUEST      0x01
#define DDC_OPCODE_VCP_REPLY        0x02
#define DDC_OPCODE_VCP_SET          0x03
#define DDC_OPCODE_VCP_RESET        0x09
#define DDC_OPCODE_START_HANDSHAKE  0x50
#define DDC_OPCODE_HANDSHAKE_REPLY  0x54
#define DDC_OPCODE_GET_HANDSHAKE_REPLY 0x55
#define DDC_OPCODE_ENABLE_3D        0x56
#define DDC_OPCODE_3D_STATUS        0x58
#define DDC_OPCODE_GET_3D_STATUS    0x59
#define DDC_OPCODE_GET_VENDOR       0x5a
#define DDC_OPCODE_VENDOR_REPLY     0x5b

#define DDC_VCP_STROBE_OVERRIDE     0x40
#define DDC_VCP_STROBE_DURATION     0x41
#define DDC_VCP_STROBE_PHASE        0x42

#define DDC_DEFAULT_DELAY_US      50000

static int verbose = 0;

#define DEBUG_PRINTF(FORMAT, ...) if (verbose) fprintf(stderr, FORMAT, ## __VA_ARGS__)

struct display_id
{
    uint16_t manufacturer;
    uint16_t product;
};

struct display_id supported_displays[] = {
    {0xd109, 0x7f2d}, // Benq XL2420Z
    {0, 0}
};

struct display_info
{
    char i2c_path[64];
    uint8_t edid[EDID_SIZE];

    struct display_id id;

    int fd;
};

struct ddc_msg
{
    int opcode;

#define DDC_MAX_DATA_LEN 34
    uint8_t data_len;
    uint8_t data[DDC_MAX_DATA_LEN];
};

static uint16_t le16(const uint8_t *bytes)
{
    return (uint16_t) bytes[0] | (((uint16_t) bytes[1]) << 8);
}

static uint16_t be16(const uint8_t *bytes)
{
    return (uint16_t) bytes[1] | (((uint16_t) bytes[0]) << 8);
}

/**
 * @brief Minimally parse the EDID
 * @param display structure containing the EDID and where to output
 * @return 1 if successful, 0 if not a valid EDID
 */
int parse_edid(struct display_info *display)
{
    // Check header
    if (memcmp("\x00\xff\xff\xff\xff\xff\xff\x00", display->edid, 8) != 0) {
        DEBUG_PRINTF("%s: Bad EDID header: %02x %02x %02x %02x %02x %02x %02x %02x\n",
                     display->i2c_path,
                     display->edid[0],
                     display->edid[1],
                     display->edid[2],
                     display->edid[3],
                     display->edid[4],
                     display->edid[5],
                     display->edid[6],
                     display->edid[7]);
        return 0;
    }

    // Check the checksum
    uint8_t sum = 0;
    int i;
    for (i = 0; i < 128; i++)
        sum += display->edid[i];
    if (sum != 0) {
        DEBUG_PRINTF("%s: Bad EDID checksum: %d\n", display->i2c_path, sum);
        return 0;
    }

    display->id.manufacturer = le16(&display->edid[8]);
    display->id.product = le16(&display->edid[10]);

    return 1;
}

static int i2c_rdwr(int fd, uint16_t addr, uint16_t flags, uint8_t *buffer, int len)
{
    struct i2c_msg msg;
    msg.addr = addr;
    msg.flags = flags;
    msg.len = len;
    msg.buf = buffer;

    struct i2c_rdwr_ioctl_data rdwr;
    rdwr.msgs = &msg;
    rdwr.nmsgs = 1;
    return ioctl(fd, I2C_RDWR, &rdwr);
}

/**
 * @brief Get information about the display connected through the specified I2C device
 * @param devpath I2C device path
 * @param display where to store the display information
 * @return 1 if successful, 0 if no display
 */
int detect_display(const char *devpath, struct display_info *display)
{
    strcpy(display->i2c_path, devpath);

    int fd = open(devpath, O_RDWR);
    if (fd < 0) {
        DEBUG_PRINTF("%s: open error: %s\n", devpath, strerror(errno));
        return 0;
    }

    // Read the EDID from the beginning
    u_int8_t edid_addr = 0;
    if (!i2c_rdwr(fd, EDID_I2C_ADDR, 0, &edid_addr, 1)) {
        DEBUG_PRINTF("%s: I2C_RDWR: %s\n", devpath, strerror(errno));
        close(fd);
        return 0;
    }
    if (!i2c_rdwr(fd, EDID_I2C_ADDR, I2C_M_RD, display->edid, EDID_SIZE)) {
        DEBUG_PRINTF("%s: I2C_RDWR: %s\n", devpath, strerror(errno));
        close(fd);
        return 0;
    }

    close(fd);

    // Parse the EDID to make sure that we weren't tricked.
    if (!parse_edid(display)) {
        DEBUG_PRINTF("%s: EDID parse failed\n", devpath);
        return 0;
    }

    return 1;
}

/**
 * @brief Return true if the specified display is in the supported list
 */
bool is_supported(struct display_info *display)
{
    struct display_id *supported_display;
    for (supported_display = supported_displays;
         supported_display->manufacturer != 0;
         supported_display++) {
        if (display->id.manufacturer == supported_display->manufacturer &&
                display->id.product == supported_display->product)
            return true;
    }

    return false;
}

/**
 * @brief Scan the I2C buses to find all of the displays
 * @param displays      an array of displays to fill out
 * @param max_displays  the max number of displays to detect
 * @return number of displays found
 */
int find_all_displays(struct display_info *displays, int max_displays)
{
    // Reset the detected displays.
    memset(displays, 0, sizeof(struct display_info) * max_displays);

    // Loop through all of the I2C buses on the system
    char path[64];
    struct display_info *display = displays;
    int i;
    for (i = 0; i < 16; i++) {
        sprintf(path, "/dev/i2c-%d", i);
        if (detect_display(path, display))
            display++;
    }

    // Return the number of displays detected
    return display - displays;
}

int send_ddc(struct display_info *display, const struct ddc_msg *msg)
{
    if (msg->data_len > DDC_MAX_DATA_LEN) {
        DEBUG_PRINTF("%s: send_ddc bad length: %d\n", display->i2c_path, msg->data_len);
        return 0;
    }
    uint8_t buffer[37];

    int msglen = msg->data_len + 4;

    buffer[0] = 0x51;                // Source
    buffer[1] = 0x80 + msg->data_len + 1; // Length of opcode + data
    buffer[2] = msg->opcode;
    memcpy(&buffer[3], &msg->data, msg->data_len);

    uint8_t csum = 0x6e;      // Destination (sent automatically by Linux)
    int i;
    for (i = 0; i < msglen - 1; i++)
        csum ^= buffer[i];
    buffer[msglen - 1] = csum;

    if (verbose) {
        fprintf(stderr, "%s: send_ddc: ", display->i2c_path);
        for (i = 0; i < msglen; i++)
            fprintf(stderr, "%02x ", buffer[i]);
        fprintf(stderr, "\n");
    }

        if (!i2c_rdwr(display->fd, DDC_I2C_ADDR, 0, buffer, msglen)) {
            DEBUG_PRINTF("%s: send_ddc write: errno=%s\n", display->i2c_path, strerror(errno));
            return 0;
        }

    return 1;
}

int receive_ddc(struct display_info *display, struct ddc_msg *msg)
{
    int i;
    uint8_t buffer[37];
    if (!i2c_rdwr(display->fd, DDC_I2C_ADDR, I2C_M_RD, buffer, sizeof(buffer))) {
        DEBUG_PRINTF("%s: receive_ddc write: errno=%s\n", display->i2c_path, strerror(errno));
        return 0;
    }

    if (verbose) {
        fprintf(stderr, "%s: receive_ddc: ", display->i2c_path);
        for (i = 0; i < (int) sizeof(buffer); i++)
            fprintf(stderr, "%02x ", buffer[i]);
        fprintf(stderr, "\n");
    }

    int len = buffer[2] - 0x80 + 2;
    if (len > (int) sizeof(buffer) || len < 3) {
        DEBUG_PRINTF("%s: receive_ddc message invalid length: %d\n", display->i2c_path, len);
        return 0;
    }

    // Check source field
    if (buffer[1] != 0x6e) {
        DEBUG_PRINTF("%s: unexpected ddc source %d\n",
                     display->i2c_path, buffer[0]);
        return 0;
    }

    // Check for null response. Let caller decide what to do.
    if (buffer[2] == 0x80) {
        DEBUG_PRINTF("%s: received null response\n", display->i2c_path);
        msg->opcode = -1;
        msg->data_len = 0;
        return 1;
    }

    // Check message length
    msg->data_len = len - 3;

    // Check checksum
    uint8_t csum = 0x50; // Implied source
    for (i = 1; i < len + 2; i++)
        csum ^= buffer[i];
    if (csum != 0) {
        DEBUG_PRINTF("%s: receive_ddc bad csum: %02x\n", display->i2c_path, csum);
        return 0;
    }

    msg->opcode = buffer[3];
    memcpy(msg->data, &buffer[4], msg->data_len);
    return 1;
}

int open_display_ddc(struct display_info *display)
{
    display->fd = open(display->i2c_path, O_RDWR);
    if (display->fd < 0) {
        DEBUG_PRINTF("%s: open ddc: %s\n", display->i2c_path, strerror(errno));
        return 0;
    }

    if (ioctl(display->fd, I2C_SLAVE, DDC_I2C_ADDR)) {
        DEBUG_PRINTF("%s: ioctl ddc I2C_SLAVE: %s\n", display->i2c_path, strerror(errno));
        close(display->fd);
        return 0;
    }

    return 1;
}

void close_display_ddc(struct display_info *display)
{
    close(display->fd);
    display->fd = -1;
}

int ddc_vcp_set(struct display_info *display,
                       uint8_t option,
                       uint16_t value)
{
    struct ddc_msg msg;
    msg.opcode = DDC_OPCODE_VCP_SET;
    msg.data_len = 3;
    msg.data[0] = option;
    msg.data[1] = (uint8_t) (value >> 8);
    msg.data[2] = (uint8_t) (value & 0xff);
    if (!send_ddc(display, &msg)) {
        DEBUG_PRINTF("%s: send_ddc(DDC_OPCODE_VCP_SET)\n", display->i2c_path);
        return 0;
    }
    usleep(DDC_DEFAULT_DELAY_US);
    return 1;
}

int ddc_vcp_get(struct display_info *display,
                uint8_t option,
                uint16_t *value)
{
    struct ddc_msg msg;
    msg.opcode = DDC_OPCODE_VCP_REQUEST;
    msg.data_len = 2;
    msg.data[0] = option;
    msg.data[1] = 0;
    if (!send_ddc(display, &msg)) {
        DEBUG_PRINTF("%s: send_ddc(DDC_OPCODE_VCP_REQUEST)\n", display->i2c_path);
        return 0;
    }
    usleep(DDC_DEFAULT_DELAY_US);

    if (!receive_ddc(display, &msg)) {
        DEBUG_PRINTF("%s: receive_ddc(DDC_OPCODE_VCP_REPLY)\n", display->i2c_path);
        return 0;
    }
    if (msg.opcode != DDC_OPCODE_VCP_REPLY) {
        DEBUG_PRINTF("%s: expected DDC_OPCODE_VCP_REPLY, but got 0x%02x\n", display->i2c_path, msg.opcode);
        return 0;
    }
    if (msg.data_len != 7) {
        DEBUG_PRINTF("%s: expected DDC_OPCODE_VCP_REPLY with len=9, but got len=%d\n", display->i2c_path, msg.data_len);
        return 0;
    }
    if (msg.data[0] != 0) {
        DEBUG_PRINTF("%s: expected DDC_OPCODE_VCP_REPLY with RC=0, but got RC=0x%02x\n", display->i2c_path, msg.data[0]);
        return 0;
    }

    *value = be16(&msg.data[5]);
    return 1;
}

int ddc_get_with_retries(struct display_info *display,
                         uint8_t option,
                         uint16_t *value)
{
    int i;
    for (i = 0; i < MAX_RETRIES; i++) {
        if (ddc_vcp_get(display, option, value))
            return 1;
    }
    return 0;
}

int ddc_vcp_set_and_check(struct display_info *display,
                          uint8_t option,
                          uint16_t value)
{
    uint16_t check;
    int i;
    for (i = 0; i < MAX_RETRIES; i++) {
        if (ddc_vcp_set(display, option, value) &&
            ddc_vcp_get(display, option, &check) &&
            value == check)
            return 1;
    }
    return 0;
}

int ddc_get_strobe_override(struct display_info *display, bool *enabled)
{
    uint16_t value;
    if (ddc_get_with_retries(display, DDC_VCP_STROBE_OVERRIDE, &value)) {
        *enabled = (value != 0);
        return 1;
    }
    return 0;
}

int ddc_set_strobe_override(struct display_info *display, bool enabled)
{
    return ddc_vcp_set_and_check(display, DDC_VCP_STROBE_OVERRIDE, enabled ? 1 : 0);
}

int ddc_get_strobe_duration(struct display_info *display, int *us)
{
    uint16_t value;
    if (ddc_get_with_retries(display, DDC_VCP_STROBE_DURATION, &value)) {
        *us = (value * 1000 + 5) / 6;
        return 1;
    }
    return 0;
}

int ddc_set_strobe_duration(struct display_info *display, int us)
{
    int value = (us * 6) / 1000;
    return ddc_vcp_set_and_check(display, DDC_VCP_STROBE_DURATION, value);
}

int ddc_get_strobe_phase(struct display_info *display, int *phase)
{
    uint16_t value;
    if (ddc_get_with_retries(display, DDC_VCP_STROBE_PHASE, &value)) {
        *phase = value;
        return 1;
    }
    return 0;
}

int ddc_set_strobe_phase(struct display_info *display, int phase)
{
    return ddc_vcp_set_and_check(display, DDC_VCP_STROBE_PHASE, phase);
}

void dump_settings(struct display_info *display)
{
    bool enabled;
    if (ddc_get_strobe_override(display, &enabled))
        printf("%s: Custom backlight strobe is %s.\n", display->i2c_path, enabled ? "enabled" : "disabled");
    else
        printf("%s: Could not get override backlight strobe setting.\n", display->i2c_path);

    int us;
    if (ddc_get_strobe_duration(display, &us))
        printf("%s: Backlight strobe duration is %d us.\n", display->i2c_path, us);
    else
        printf("%s: Could not get strobe duration.\n", display->i2c_path);

    int phase;
    if (ddc_get_strobe_phase(display, &phase))
        printf("%s: Backlight strobe phase is %d.\n", display->i2c_path, phase);
    else
        printf("%s: Could not get strobe phase.\n", display->i2c_path);
}

void usage(const char *argv0)
{
    fprintf(stderr, "Backlight strobe control utility\n");
    fprintf(stderr, "Version " VERSION "\n\n");
    fprintf(stderr, "%s [options]\n", argv0);
    fprintf(stderr, "  -d disable backlight strobe overrides\n");
    fprintf(stderr, "  -e enable backlight strobe overrides\n");
    fprintf(stderr, "  -f force operation on unsupported display\n");
    fprintf(stderr, "  -g get the current settings\n");
    fprintf(stderr, "  -o <path> set path to i2c device (e.g., /dev/i2c-0)\n");
    fprintf(stderr, "  -p <phase> backlight strobe phase (0-47)\n");
    fprintf(stderr, "  -t <duration in us> backlight strobe time in microseconds (167-5000)\n");
    fprintf(stderr, "  -v verbose\n");
}

int main(int argc, char *argv[])
{
    struct display_info displays[MAX_DISPLAYS];
    int num_displays = 0;
    bool enable_strobe_override = false;
    bool disable_strobe_override = false;
    bool get_current_settings = false;
    int strobe_phase = -1;
    int strobe_time_us = -1;
    bool force = false;

    int opt;
    while ((opt = getopt(argc, argv, "defgo:p:t:v")) != -1) {
        switch (opt) {
        case 'd':
            disable_strobe_override = true;
            break;

        case 'e':
            enable_strobe_override = true;
            break;

        case 'f':
            force = true;
            break;

        case 'g':
            get_current_settings = true;
            break;

        case 'o':
            if (!detect_display(optarg, &displays[0]))
                errx(EXIT_FAILURE, "Display not found at %s. Run \"modprobe i2c-dev\" or check permissions.", optarg);
            num_displays = 1;
            break;

        case 'p':
            enable_strobe_override = true;
            strobe_phase = strtol(optarg, NULL, 0);
            if (strobe_phase < 0 || strobe_phase > 47)
                errx(EXIT_FAILURE, "Strobe phase must be between 0 and 47.");
            break;

        case 't':
            enable_strobe_override = true;
            strobe_time_us = strtol(optarg, NULL, 0);
            if (strobe_time_us < 167 || strobe_time_us > 5000)
                errx(EXIT_FAILURE, "Strobe duration must be between 170 us and 5000 us.");
            break;

        case 'v':
            verbose++;
            break;

        case 'h':
        default:
            usage(argv[0]);
            return EXIT_FAILURE;
        }
    }

    if (!disable_strobe_override &&
        !enable_strobe_override &&
        strobe_phase == -1 &&
        strobe_time_us == -1) {
        // Not setting anything so check if we're getting settings
        if (!get_current_settings) {
            // Doing nothing -> show usage
            usage(argv[0]);
            return EXIT_FAILURE;
        }
    } else {
        if (get_current_settings)
            errx(EXIT_FAILURE, "Don't set anything if you want to get the current settings.");
    }

    if (disable_strobe_override && enable_strobe_override)
        errx(EXIT_FAILURE, "Cannot both enable and disable the backlight strobe override");

    if (num_displays == 0)
        num_displays = find_all_displays(displays, MAX_DISPLAYS);
    if (num_displays == 0)
        errx(EXIT_FAILURE, "No displays detected. Run \"modprobe i2c-dev\" or check permissions.");

    printf("%d display(s) detected.\n", num_displays);
    int i;
    for (i = 0; i < num_displays; i++) {
        printf("%s: Detected display (Manufacturer ID=%04x, Product ID=%04x).\n",
               displays[i].i2c_path,
               displays[i].id.manufacturer,
               displays[i].id.product);

        if (!is_supported(&displays[i])) {
            printf("%s: Display not supported.\n", displays[i].i2c_path);
            if (!force)
                continue;
        }

        if (open_display_ddc(&displays[i])) {

            if (get_current_settings)
                dump_settings(&displays[i]);

            if (enable_strobe_override && !ddc_set_strobe_override(&displays[i], true))
                printf("%s: Could not override backlight strobe setting.\n", displays[i].i2c_path);

            if (disable_strobe_override && !ddc_set_strobe_override(&displays[i], false))
                printf("%s: Could not disable the backlight strobe override.\n", displays[i].i2c_path);

            if (strobe_phase != -1 && !ddc_set_strobe_phase(&displays[i], strobe_phase))
                printf("%s: Could not set backlight strobe phase.\n", displays[i].i2c_path);

            if (strobe_time_us != -1 && !ddc_set_strobe_duration(&displays[i], strobe_time_us))
                printf("%s: Could not set backlight strobe duration.\n", displays[i].i2c_path);

            close_display_ddc(&displays[i]);
        }
    }

    return 0;
}
