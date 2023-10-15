/* SPDX-FileCopyrightText: 2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * @file openvas.h
 * @brief Headers for OpenVAS entry point.
 */

#ifndef OPENVAS_H
#define OPENVAS_H

int
openvas (int, char **, char **);

// CUSTOM CHANGE : openvas-light
// add start single task
// add flush all kbs
void start_single_task_scan (char * scan_id);
int flush_all_kbs (void);
// END CUSTOM CHANGE

#endif /* not OPENVAS_H */
