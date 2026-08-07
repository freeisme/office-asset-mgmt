SET NAMES utf8mb4;

INSERT INTO non_asset_type (type_code, type_name, unit_name)
VALUES
  ('monitor', '显示屏', '件'),
  ('mouse', '鼠标', '件'),
  ('keyboard', '键盘', '件'),
  ('docking_station', '拓展坞', '件'),
  ('headset', '耳机', '件'),
  ('usb_hub', 'USB集线器', '件'),
  ('webcam', '摄像头', '件')
ON DUPLICATE KEY UPDATE
  type_name = VALUES(type_name),
  unit_name = VALUES(unit_name),
  is_active = 1,
  updated_at = CURRENT_TIMESTAMP;
