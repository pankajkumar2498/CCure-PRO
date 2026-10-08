/**
 * The application's icon set — one geometry for every module.
 *
 * Each icon is a list of SVG shapes on a 24 × 24 grid, drawn with a 2px round
 * stroke in `currentColor` by CcureIcon. It is the geometry the shell's own
 * navigation icons have always used (Feather-style outline, MIT), gathered here
 * so Common, Audit and every later module draw the same marks.
 *
 * Why not the official UX4G icons: those are an icon font
 * (`ux4g-icon-outlined`), and the approved B.1 font policy deliberately does not
 * ship the five Material Icons families. Changing that is a typography decision,
 * not an icon one.
 *
 * Names describe the shape, not the use ("download", not "export-report"), so the
 * same mark means the same thing wherever it appears. Add a shape here rather
 * than drawing an <svg> in a page.
 */

const line = (x1, y1, x2, y2) => ["line", { x1, y1, x2, y2 }];
const circle = (cx, cy, r) => ["circle", { cx, cy, r }];
const path = (d) => ["path", { d }];
const polyline = (points) => ["polyline", { points }];
const polygon = (points) => ["polygon", { points }];
const rect = (x, y, width, height, rx = 0) => [
  "rect",
  rx ? { x, y, width, height, rx, ry: rx } : { x, y, width, height },
];

const TRAY = "M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4";
const BOX =
  "M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z";
const DRIVE =
  "M5.45 5.11L2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z";

export const ICONS = {
  // Sidebar marks first drawn in Audit's AppLayout, kept to their exact paths.
  archive: [path("M21 8v13H3V8M1 3h22v5H1zM10 12h4")],
  dashboard: [
    path("M3 13h8V3H3v10zM13 21h8V11h-8v10zM13 3v6h8V3h-8zM3 21h8v-6H3v6z"),
  ],
  grid: [path("M3 3h7v7H3zM14 3h7v7h-7zM14 14h7v7h-7zM3 14h7v7H3z")],
  plus: [line(12, 5, 12, 19), line(5, 12, 19, 12)],
  topology: [
    path(
      "M12 2a3 3 0 0 0-3 3c0 1.1.6 2 1.5 2.6L9 10l-4 2-2.5-1.5A3 3 0 0 0 0 13a3 3 0 0 0 5 2.2l4-2L12 15l3-1.8 4 2A3 3 0 0 0 24 13a3 3 0 0 0-2.5-2.5L19 12l-4-2-1.5-2.4A3 3 0 0 0 15 5a3 3 0 0 0-3-3z",
    ),
  ],
  activity: [polyline("22 12 18 12 15 21 9 3 6 12 2 12")],
  "alert-circle": [
    circle(12, 12, 10),
    line(12, 8, 12, 12),
    line(12, 16, 12.01, 16),
  ],
  "alert-octagon": [
    polygon(
      "7.86 2 16.14 2 22 7.86 22 16.14 16.14 22 7.86 22 2 16.14 2 7.86 7.86 2",
    ),
    line(12, 8, 12, 12),
    line(12, 16, 12.01, 16),
  ],
  "alert-triangle": [
    path(
      "M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z",
    ),
    line(12, 9, 12, 13),
    line(12, 17, 12.01, 17),
  ],
  "arrow-right": [line(5, 12, 19, 12), polyline("12 5 19 12 12 19")],
  "bar-chart": [line(18, 20, 18, 10), line(12, 20, 12, 4), line(6, 20, 6, 14)],
  bell: [
    path("M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"),
    path("M13.73 21a2 2 0 0 1-3.46 0"),
  ],
  "book-open": [
    path("M2 3h6a4 4 0 0 1 4 4v14a3 3 0 0 0-3-3H2z"),
    path("M22 3h-6a4 4 0 0 0-4 4v14a3 3 0 0 1 3-3h7z"),
  ],
  briefcase: [
    rect(2, 7, 20, 14, 2),
    path("M16 21V5a2 2 0 0 0-2-2h-4a2 2 0 0 0-2 2v16"),
  ],
  calendar: [
    rect(3, 4, 18, 18, 2),
    line(16, 2, 16, 6),
    line(8, 2, 8, 6),
    line(3, 10, 21, 10),
  ],
  check: [polyline("20 6 9 17 4 12")],
  "check-circle": [
    path("M22 11.08V12a10 10 0 1 1-5.93-9.14"),
    polyline("22 4 12 14.01 9 11.01"),
  ],
  "chevrons-down": [polyline("7 13 12 18 17 13"), polyline("7 6 12 11 17 6")],
  "chevrons-up": [polyline("17 11 12 6 7 11"), polyline("17 18 12 13 7 18")],
  clipboard: [
    path(
      "M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2",
    ),
    rect(8, 2, 8, 4, 1),
  ],
  clock: [circle(12, 12, 10), polyline("12 6 12 12 16 14")],
  compass: [
    circle(12, 12, 10),
    polygon("16.24 7.76 14.12 14.12 7.76 16.24 9.88 9.88 16.24 7.76"),
  ],
  cpu: [
    rect(4, 4, 16, 16, 2),
    rect(9, 9, 6, 6),
    line(9, 1, 9, 4),
    line(15, 1, 15, 4),
    line(9, 20, 9, 23),
    line(15, 20, 15, 23),
    line(20, 9, 23, 9),
    line(20, 14, 23, 14),
    line(1, 9, 4, 9),
    line(1, 14, 4, 14),
  ],
  crosshair: [
    circle(12, 12, 10),
    line(22, 12, 18, 12),
    line(6, 12, 2, 12),
    line(12, 6, 12, 2),
    line(12, 22, 12, 18),
  ],
  download: [path(TRAY), polyline("7 10 12 15 17 10"), line(12, 15, 12, 3)],
  edit: [path("M17 3a2.828 2.828 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5L17 3z")],
  eye: [
    path("M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"),
    circle(12, 12, 3),
  ],
  "eye-off": [
    path(
      "M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24",
    ),
    line(1, 1, 23, 23),
  ],
  "fast-forward": [
    polygon("13 19 22 12 13 5 13 19"),
    polygon("2 19 11 12 2 5 2 19"),
  ],
  file: [
    path("M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"),
    polyline("13 2 13 9 20 9"),
  ],
  "file-text": [
    path("M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"),
    polyline("14 2 14 8 20 8"),
    line(16, 13, 8, 13),
    line(16, 17, 8, 17),
    polyline("10 9 9 9 8 9"),
  ],
  flag: [
    path("M4 15s1-1 4-1 5 2 8 2 4-1 4-1V3s-1 1-4 1-5-2-8-2-4 1-4 1z"),
    line(4, 22, 4, 15),
  ],
  folder: [
    path(
      "M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z",
    ),
  ],
  globe: [
    circle(12, 12, 10),
    line(2, 12, 22, 12),
    path(
      "M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z",
    ),
  ],
  "hard-drive": [
    line(22, 12, 2, 12),
    path(DRIVE),
    line(6, 16, 6.01, 16),
    line(10, 16, 10.01, 16),
  ],
  "help-circle": [
    circle(12, 12, 10),
    path("M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"),
    line(12, 17, 12.01, 17),
  ],
  inbox: [polyline("22 12 16 12 14 15 10 15 8 12 2 12"), path(DRIVE)],
  info: [circle(12, 12, 10), line(12, 16, 12, 12), line(12, 8, 12.01, 8)],
  key: [
    path(
      "M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4",
    ),
  ],
  layers: [
    polygon("12 2 2 7 12 12 22 7 12 2"),
    polyline("2 17 12 22 22 17"),
    polyline("2 12 12 17 22 12"),
  ],
  link: [
    path("M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"),
    path("M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"),
  ],
  list: [
    line(8, 6, 21, 6),
    line(8, 12, 21, 12),
    line(8, 18, 21, 18),
    line(3, 6, 3.01, 6),
    line(3, 12, 3.01, 12),
    line(3, 18, 3.01, 18),
  ],
  lock: [rect(3, 11, 18, 11, 2), path("M7 11V7a5 5 0 0 1 10 0v4")],
  "log-out": [
    path("M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"),
    polyline("16 17 21 12 16 7"),
    line(21, 12, 9, 12),
  ],
  map: [
    polygon("1 6 1 22 8 18 16 22 23 18 23 2 16 6 8 2 1 6"),
    line(8, 2, 8, 18),
    line(16, 6, 16, 22),
  ],
  maximize: [
    path(
      "M8 3H5a2 2 0 0 0-2 2v3m18 0V5a2 2 0 0 0-2-2h-3m0 18h3a2 2 0 0 0 2-2v-3M3 16v3a2 2 0 0 0 2 2h3",
    ),
  ],
  menu: [line(3, 12, 21, 12), line(3, 6, 21, 6), line(3, 18, 21, 18)],
  "message-square": [
    path("M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"),
  ],
  minimize: [
    polyline("4 14 10 14 10 20"),
    polyline("20 10 14 10 14 4"),
    line(14, 10, 21, 3),
    line(3, 21, 10, 14),
  ],
  monitor: [rect(2, 3, 20, 14, 2), line(8, 21, 16, 21), line(12, 17, 12, 21)],
  moon: [path("M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z")],
  package: [
    line(16.5, 9.4, 7.5, 4.21),
    path(BOX),
    polyline("3.27 6.96 12 12.01 20.73 6.96"),
    line(12, 22.08, 12, 12),
  ],
  paperclip: [
    path(
      "M21.44 11.05l-9.19 9.19a6 6 0 0 1-8.49-8.49l9.19-9.19a4 4 0 0 1 5.66 5.66l-9.2 9.19a2 2 0 0 1-2.83-2.83l8.49-8.48",
    ),
  ],
  "pause-circle": [
    circle(12, 12, 10),
    line(10, 15, 10, 9),
    line(14, 15, 14, 9),
  ],
  phone: [
    path(
      "M22 16.92v3a2 2 0 0 1-2.18 2 19.79 19.79 0 0 1-8.63-3.07 19.5 19.5 0 0 1-6-6 19.79 19.79 0 0 1-3.07-8.67A2 2 0 0 1 4.11 2h3a2 2 0 0 1 2 1.72 12.84 12.84 0 0 0 .7 2.81 2 2 0 0 1-.45 2.11L8.09 9.91a16 16 0 0 0 6 6l1.27-1.27a2 2 0 0 1 2.11-.45 12.84 12.84 0 0 0 2.81.7A2 2 0 0 1 22 16.92z",
    ),
  ],
  play: [polygon("5 3 19 12 5 21 5 3")],
  power: [path("M18.36 6.64a9 9 0 1 1-12.73 0"), line(12, 2, 12, 12)],
  printer: [
    polyline("6 9 6 2 18 2 18 9"),
    path(
      "M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2",
    ),
    rect(6, 14, 12, 8),
  ],
  radio: [
    circle(12, 12, 2),
    path(
      "M16.24 7.76a6 6 0 0 1 0 8.49m-8.48-.01a6 6 0 0 1 0-8.49m11.31-2.82a10 10 0 0 1 0 14.14m-14.14 0a10 10 0 0 1 0-14.14",
    ),
  ],
  "refresh-cw": [
    polyline("23 4 23 10 17 10"),
    polyline("1 20 1 14 7 14"),
    path(
      "M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15",
    ),
  ],
  repeat: [
    polyline("17 1 21 5 17 9"),
    path("M3 11V9a4 4 0 0 1 4-4h14"),
    polyline("7 23 3 19 7 15"),
    path("M21 13v2a4 4 0 0 1-4 4H3"),
  ],
  "rotate-ccw": [
    polyline("1 4 1 10 7 10"),
    path("M3.51 15a9 9 0 1 0 2.13-9.36L1 10"),
  ],
  save: [
    path("M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"),
    polyline("17 21 17 13 7 13 7 21"),
    polyline("7 3 7 8 15 8"),
  ],
  search: [circle(11, 11, 8), line(21, 21, 16.65, 16.65)],
  server: [
    rect(2, 2, 20, 8, 2),
    rect(2, 14, 20, 8, 2),
    line(6, 6, 6.01, 6),
    line(6, 18, 6.01, 18),
  ],
  settings: [
    path(
      "M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6zM19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06A1.65 1.65 0 0 0 15 19.4a1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.6 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 1 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.6a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09A1.65 1.65 0 0 0 15 4.6a1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9c.14.31.22.65.22 1h.38a2 2 0 1 1 0 4h-.38c0 .35-.08.69-.22 1z",
    ),
  ],
  "share-2": [
    circle(18, 5, 3),
    circle(6, 12, 3),
    circle(18, 19, 3),
    line(8.59, 13.51, 15.42, 17.49),
    line(15.41, 6.51, 8.59, 10.49),
  ],
  shield: [path("M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z")],
  shuffle: [
    polyline("16 3 21 3 21 8"),
    line(4, 20, 21, 3),
    polyline("21 16 21 21 16 21"),
    line(15, 15, 21, 21),
    line(4, 4, 9, 9),
  ],
  slash: [circle(12, 12, 10), line(4.93, 4.93, 19.07, 19.07)],
  sliders: [
    line(4, 21, 4, 14),
    line(4, 10, 4, 3),
    line(12, 21, 12, 12),
    line(12, 8, 12, 3),
    line(20, 21, 20, 16),
    line(20, 12, 20, 3),
    line(1, 14, 7, 14),
    line(9, 8, 15, 8),
    line(17, 16, 23, 16),
  ],
  "stop-circle": [circle(12, 12, 10), rect(9, 9, 6, 6)],
  sun: [
    circle(12, 12, 5),
    line(12, 1, 12, 3),
    line(12, 21, 12, 23),
    line(4.22, 4.22, 5.64, 5.64),
    line(18.36, 18.36, 19.78, 19.78),
    line(1, 12, 3, 12),
    line(21, 12, 23, 12),
    line(4.22, 19.78, 5.64, 18.36),
    line(18.36, 5.64, 19.78, 4.22),
  ],
  tag: [
    path(
      "M20.59 13.41l-7.17 7.17a2 2 0 0 1-2.83 0L2 12V2h10l8.59 8.59a2 2 0 0 1 0 2.82z",
    ),
    line(7, 7, 7.01, 7),
  ],
  target: [circle(12, 12, 10), circle(12, 12, 6), circle(12, 12, 2)],
  tool: [
    path(
      "M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z",
    ),
  ],
  trash: [
    polyline("3 6 5 6 21 6"),
    path(
      "M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2",
    ),
    line(10, 11, 10, 17),
    line(14, 11, 14, 17),
  ],
  "trending-up": [
    polyline("23 6 13.5 15.5 8.5 10.5 1 18"),
    polyline("17 6 23 6 23 12"),
  ],
  unlock: [rect(3, 11, 18, 11, 2), path("M7 11V7a5 5 0 0 1 9.9-1")],
  upload: [path(TRAY), polyline("17 8 12 3 7 8"), line(12, 3, 12, 15)],
  user: [path("M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"), circle(12, 7, 4)],
  users: [
    path("M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"),
    circle(9, 7, 4),
    path("M23 21v-2a4 4 0 0 0-3-3.87"),
    path("M16 3.13a4 4 0 0 1 0 7.75"),
  ],
  wifi: [
    path("M5 12.55a11 11 0 0 1 14.08 0"),
    path("M1.42 9a16 16 0 0 1 21.16 0"),
    path("M8.53 16.11a6 6 0 0 1 6.95 0"),
    line(12, 20, 12.01, 20),
  ],
  x: [line(18, 6, 6, 18), line(6, 6, 18, 18)],
  "x-circle": [circle(12, 12, 10), line(15, 9, 9, 15), line(9, 9, 15, 15)],
  zap: [polygon("13 2 3 14 12 14 11 22 21 10 12 10 13 2")],
};

export const ICON_NAMES = Object.freeze(Object.keys(ICONS).sort());
