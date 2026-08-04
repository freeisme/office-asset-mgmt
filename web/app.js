const UI_STORAGE_KEY = "office-asset-center-ui-v1";
const API_STATE_URL = "/api/state";
const API_AUDIT_LOGS_URL = "/api/audit-logs";
const API_AUTH_SESSION_URL = "/api/auth/session";
const API_AUTH_LOGIN_URL = "/api/auth/login";
const API_AUTH_BOOTSTRAP_STATUS_URL = "/api/auth/bootstrap-status";
const API_AUTH_BOOTSTRAP_URL = "/api/auth/bootstrap";
const API_AUTH_LOGOUT_URL = "/api/auth/logout";
const API_AUTH_CHANGE_PASSWORD_URL = "/api/auth/change-password";
const API_USERS_URL = "/api/users";
const API_SETTINGS_URL = "/api/settings";
const API_BACKUPS_URL = "/api/backups";
const API_UPDATE_CHECK_URL = "/api/updates/check";

const pageMeta = {
  dashboard: {
    title: "资产总览",
    description: "掌握办公设备分布、使用状态和人员领用情况。",
  },
  computers: {
    title: "办公电脑",
    description: "维护电脑资产台账、归属人员和 IT 资产状态。",
  },
  employees: {
    title: "使用人员",
    description: "按组织架构树查看人员和名下办公设备。",
  },
  leftEmployees: {
    title: "离职人员",
    description: "保存离职人员资料、离职信息和离职时使用设备快照。",
  },
  inventory: {
    title: "IT物资",
    description: "管理电脑、显示屏和其他 IT 物资库存、采购入库与分配状态。",
  },
  dictionary: {
    title: "基础字典",
    description: "维护组织架构树和非资产设备类型。",
  },
  audit: {
    title: "操作日志",
    description: "记录设备状态变更和人员 IT 物资领用变化。",
  },
  settings: {
    title: "设置",
    description: "管理系统参数、账号和个人登录安全。",
  },
};

const statusLabels = {
  in_use: "在用",
  idle: "闲置",
  repair: "维修",
  retired: "报废",
  lost: "丢失",
  active: "在职",
  inactive: "停用",
  left: "离职",
};

const roleLabels = {
  admin: "管理员",
  operator: "操作员",
  viewer: "只读用户",
};

const deviceTypeLabels = {
  laptop: "笔记本",
  desktop: "台式机",
  workstation: "工作站",
  mini_pc: "迷你主机",
};

let state = loadInitialState();
let remoteSyncQueue = Promise.resolve();
let auditFilterRefreshTimer = 0;
let pendingDeviceSave = null;
let pendingLeaveRecovery = null;
let pendingDeviceRecovery = null;
let employeeSearchDrafts = {};
let authState = { authenticated: false, user: null, bootstrapRequired: false };
let settingsState = {
  settings: {},
  users: [],
  backups: [],
  loaded: false,
  updateStatus: null,
  updateChecking: false,
};
let authBootPromise = null;

function authRoleLabel(role) {
  return roleLabels[role] || role || "未知角色";
}

function isAdminUser() {
  return authState.user?.role === "admin";
}

function canWriteState() {
  return ["admin", "operator"].includes(authState.user?.role);
}

function createId(prefix) {
  if (window.crypto && typeof window.crypto.randomUUID === "function") {
    return `${prefix}-${window.crypto.randomUUID()}`;
  }
  return `${prefix}-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

function getSeedState() {
  const orgs = [
    { id: "1", code: "KPLUS", name: "K+", parentId: "", sortOrder: 10 },
    { id: "2", code: "SZNS", name: "苏州诺思", parentId: "1", sortOrder: 10 },
    { id: "3", code: "NTKD", name: "南通科德", parentId: "1", sortOrder: 20 },
  ];

  return {
    page: "dashboard",
    filters: {
      computers: "",
      computerStatus: "",
      employees: "",
      employeeAssetSearch: "",
      employeeStatus: "",
      employeeOrg: "",
      employeeDevice: "",
      leftEmployees: "",
      dictionary: "",
      inventorySearch: "",
      inventoryType: "",
      inventoryBrand: "",
      auditSearch: "",
      auditAction: "",
      auditCategory: "",
      auditEntityType: "",
      auditEmployee: "",
      auditStartDate: "",
      auditEndDate: "",
    },
    selectedComputerIds: [],
    selectedEmployeeIds: [],
    expandedOrgIds: orgs.map((org) => org.id),
    expandedInventoryTypeIds: [],
    expandedInventoryBrandIds: [],
    orgs,
    nonAssetTypes: [
      { id: "mouse", code: "mouse", name: "鼠标", unit: "件" },
      { id: "keyboard", code: "keyboard", name: "键盘", unit: "件" },
      { id: "docking_station", code: "docking_station", name: "拓展坞", unit: "件" },
      { id: "headset", code: "headset", name: "耳机", unit: "件" },
      { id: "usb_hub", code: "usb_hub", name: "USB集线器", unit: "件" },
      { id: "webcam", code: "webcam", name: "摄像头", unit: "件" },
      { id: "computer", code: "computer", name: "电脑", unit: "台" },
    ],
    inventoryBrands: [],
    inventoryModels: [],
    inventoryMovementLogs: [],
    inventoryPurchaseLogs: [],
    stateRevision: 0,
    employees: [],
    leftEmployees: [],
    computers: [],
    auditLogs: [],
    auditLogTotal: 0,
  };
}

function loadUiState() {
  try {
    const saved = window.localStorage.getItem(UI_STORAGE_KEY);
    if (saved) return JSON.parse(saved);
  } catch (error) {
    console.warn("Unable to load local UI state", error);
  }
  return {};
}

function extractUiState(value) {
  return {
    page: value.page,
    filters: value.filters,
    selectedComputerIds: value.selectedComputerIds,
    selectedEmployeeIds: value.selectedEmployeeIds,
    expandedOrgIds: value.expandedOrgIds,
    expandedInventoryTypeIds: value.expandedInventoryTypeIds,
    expandedInventoryBrandIds: value.expandedInventoryBrandIds,
  };
}

function extractDataState(value) {
  return {
    orgs: value.orgs,
    nonAssetTypes: value.nonAssetTypes,
    inventoryBrands: value.inventoryBrands,
    inventoryModels: value.inventoryModels,
    inventoryMovementLogs: value.inventoryMovementLogs,
    inventoryPurchaseLogs: value.inventoryPurchaseLogs,
    employees: value.employees,
    leftEmployees: value.leftEmployees,
    computers: value.computers,
    stateRevision: value.stateRevision || 0,
  };
}

function loadInitialState() {
  return normalizeState({
    ...getSeedState(),
    ...loadUiState(),
  });
}

function normalizeState(value) {
  const seed = getSeedState();
  const orgs = normalizeOrgs(Array.isArray(value.orgs) ? value.orgs : seed.orgs);
  const expandedOrgIds = Array.isArray(value.expandedOrgIds) ? value.expandedOrgIds : orgs.map((org) => org.id);
  let nonAssetTypes = Array.isArray(value.nonAssetTypes) ? value.nonAssetTypes : seed.nonAssetTypes;
  if (!nonAssetTypes.some((type) => isComputerInventoryType(type))) {
    nonAssetTypes = nonAssetTypes.concat([{ id: "computer", code: "computer", name: "电脑", unit: "台" }]);
  }
  const inventoryBrands = Array.isArray(value.inventoryBrands)
    ? value.inventoryBrands.map((brand) => ({
        id: brand.id || createId("brand"),
        typeId: brand.typeId || "",
        name: brand.name || brand.brandName || "",
        sortOrder: Math.max(0, Number(brand.sortOrder ?? 1000)),
      }))
    : seed.inventoryBrands;
  const inventoryModels = Array.isArray(value.inventoryModels)
    ? value.inventoryModels.map((model) => {
        const type = nonAssetTypes.find((item) => item.id === (model.typeId || ""));
        const computerModel = isComputerInventoryType(type);
        return {
          id: model.id || createId("model"),
          typeId: model.typeId || "",
          brandId: model.brandId || "",
          name: model.name || model.modelName || "",
          batchKey: model.batchKey || "",
          quantity: Math.max(0, Number(model.quantity ?? 0)),
          inboundDate: computerModel ? model.inboundDate || "" : "",
          cpu: computerModel ? model.cpu || "" : "",
          memory: computerModel ? model.memory || "" : "",
          storage: computerModel ? model.storage || "" : "",
          gpu: computerModel ? model.gpu || "" : "",
          sortOrder: Math.max(0, Number(model.sortOrder ?? 1000)),
        };
      })
    : seed.inventoryModels;
  const inventoryTypeIds = new Set(nonAssetTypes.map((type) => type.id));
  const inventoryBrandIds = new Set(inventoryBrands.map((brand) => brand.id));
  const expandedInventoryTypeIds = Array.isArray(value.expandedInventoryTypeIds)
    ? value.expandedInventoryTypeIds.filter((id) => inventoryTypeIds.has(id))
    : nonAssetTypes.map((type) => type.id);
  const expandedInventoryBrandIds = Array.isArray(value.expandedInventoryBrandIds)
    ? value.expandedInventoryBrandIds.filter((id) => inventoryBrandIds.has(id))
    : [];
  const employeeIds = new Set((Array.isArray(value.employees) ? value.employees : seed.employees).map((employee) => employee.id));
  const computerIds = new Set((Array.isArray(value.computers) ? value.computers : seed.computers).map((computer) => computer.id));

  return {
    ...seed,
    ...value,
    filters: { ...seed.filters, ...(value.filters || {}) },
    selectedComputerIds: Array.isArray(value.selectedComputerIds)
      ? value.selectedComputerIds.filter((id) => computerIds.has(id))
      : [],
    stateRevision: Math.max(0, Number(value.stateRevision || 0)),
    selectedEmployeeIds: Array.isArray(value.selectedEmployeeIds)
      ? value.selectedEmployeeIds.filter((id) => employeeIds.has(id))
      : [],
    expandedOrgIds,
    expandedInventoryTypeIds,
    expandedInventoryBrandIds,
    orgs,
    nonAssetTypes,
    inventoryBrands,
    inventoryModels,
    inventoryMovementLogs: Array.isArray(value.inventoryMovementLogs)
      ? value.inventoryMovementLogs.map((log) => ({
          id: String(log.id || createId("invlog")),
          direction: log.direction === "decrease" ? "decrease" : "increase",
          typeName: log.typeName || "",
          brandName: log.brandName || "",
          modelName: log.modelName || "",
          quantity: Math.max(1, Number(log.quantity || 1)),
          sourceLabel: log.sourceLabel || "",
          targetLabel: log.targetLabel || "",
          note: log.note || "",
          relatedEmployeeNo: log.relatedEmployeeNo || "",
          relatedEmployeeName: log.relatedEmployeeName || "",
          triggerAction: log.triggerAction || "manual",
          occurredAt: log.occurredAt || "",
        }))
      : [],
    inventoryPurchaseLogs: Array.isArray(value.inventoryPurchaseLogs)
      ? value.inventoryPurchaseLogs.map((log) => ({
          id: String(log.id || createId("purchase")),
          typeName: log.typeName || "",
          brandName: log.brandName || "",
          modelName: log.modelName || "",
          typeId: String(log.typeId || ""),
          brandId: String(log.brandId || ""),
          modelId: String(log.modelId || ""),
          quantity: Math.max(1, Number(log.quantity || 1)),
          inboundDate: log.inboundDate || "",
          cpu: log.cpu || "",
          memory: log.memory || "",
          storage: log.storage || "",
          gpu: log.gpu || "",
          sourceLabel: log.sourceLabel || "",
          note: log.note || "",
          sourceMovementLogId: log.sourceMovementLogId || "",
          createdAt: log.createdAt || "",
        }))
      : [],
    auditLogs: Array.isArray(value.auditLogs)
      ? value.auditLogs.map((log) => ({
          id: String(log.id || ""),
          actionType: log.actionType || "",
          entityType: log.entityType || "",
          category: log.category || "",
          categoryLabel: log.categoryLabel || "",
          changeLabel: log.changeLabel || "",
          entityId: log.entityId || "",
          entityName: log.entityName || "",
          employeeId: log.employeeId || "",
          employeeName: log.employeeName || "",
          deviceName: log.deviceName || "",
          oldValue: log.oldValue ?? null,
          newValue: log.newValue ?? null,
          summary: log.summary || "",
          actor: log.actor || "web",
          source: log.source || "web",
          createdAt: log.createdAt || "",
        }))
      : seed.auditLogs,
    auditLogTotal: Math.max(
      0,
      Number(value.auditLogTotal ?? (Array.isArray(value.auditLogs) ? value.auditLogs.length : seed.auditLogTotal)),
    ),
    employees: Array.isArray(value.employees)
      ? value.employees.map((employee) => {
          const monitors = Array.isArray(employee.monitors)
            ? employee.monitors.map((monitor) => ({
                id: monitor.id || createId("mon"),
                typeId: monitor.typeId || defaultMonitorTypeId(),
                brand: monitor.brand || monitor.displayName || "",
                model: monitor.model || "",
                inventoryBrandId: monitor.inventoryBrandId || "",
                inventoryModelId: monitor.inventoryModelId || "",
                stockAdjusted: Boolean(monitor.stockAdjusted),
              }))
            : [];
          const nonAssetItems = Array.isArray(employee.nonAssetItems)
            ? employee.nonAssetItems.map((item) => ({
                id: item.id || createId("na"),
                typeId: item.typeId || "mouse",
                brand: item.brand || "",
                model: item.model || "",
                quantity: Math.max(1, Number(item.quantity || 1)),
                inventoryBrandId: item.inventoryBrandId || "",
                inventoryModelId: item.inventoryModelId || "",
                stockAdjusted: Boolean(item.stockAdjusted),
              }))
            : Object.entries(employee.nonAssets || {}).reduce((items, [typeId, quantity]) => {
                const count = Math.max(0, Number(quantity || 0));
                if (count) {
                  items.push({
                    id: createId("na"),
                    typeId,
                    brand: "",
                    model: "",
                    quantity: count,
                    inventoryBrandId: "",
                    inventoryModelId: "",
                    stockAdjusted: false,
                  });
                }
                return items;
              }, []);
          const normalizedEmployee = {
            ...employee,
            monitors,
            nonAssetItems,
            nonAssets: {},
          };
          syncNonAssetAggregate(normalizedEmployee);
          return normalizedEmployee;
        })
      : seed.employees,
    leftEmployees: Array.isArray(value.leftEmployees)
      ? value.leftEmployees.map((item) => ({
          id: item.id || createId("left"),
          sourceEmployeeId: item.sourceEmployeeId || "",
          employeeNo: item.employeeNo || "",
          name: item.name || "",
          orgId: item.orgId || "",
          orgPath: item.orgPath || "",
          department: item.department || "",
          position: item.position || "",
          email: item.email || "",
          mobile: item.mobile || "",
          leaveDate: item.leaveDate || "",
          leaveInfo: item.leaveInfo || "",
          leaveRemark: item.leaveRemark || "",
          archivedAt: item.archivedAt || "",
          devices: Array.isArray(item.devices)
            ? item.devices.map((device) => ({
                category: device.category || "other",
                label: device.label || "",
                detail: device.detail || "",
                quantity: Math.max(1, Number(device.quantity || 1)),
                typeId: device.typeId || "",
                typeName: device.typeName || "",
                brandId: device.brandId || "",
                modelId: device.modelId || "",
                brand: device.brand || "",
                model: device.model || "",
              }))
            : [],
        }))
      : seed.leftEmployees,
    computers: Array.isArray(value.computers)
      ? value.computers.map((computer) => normalizeComputerRecord(computer, employeeIds))
      : seed.computers,
  };
}

function normalizeOrgs(orgs) {
  const hasParentField = orgs.some((org) => Object.prototype.hasOwnProperty.call(org, "parentId"));
  const hqOrg = orgs.find((org) => org.code === "HQ") || orgs[0];
  return orgs.map((org, index) => ({
    ...org,
    parentId: hasParentField ? String(org.parentId || "") : org.id === hqOrg?.id ? "" : hqOrg?.id || "",
    sortOrder: Number(org.sortOrder ?? (index + 1) * 10),
  }));
}

const orgCodeOverrides = {
  "产品部": "CP",
  "流程IT与质量部": "ITQ",
  "稽核审计与持续改善组": "JHSJ",
  "稽核审计与改善组": "JHSJ",
  "财务部": "CW",
  "人事行政部": "RSXZ",
  "研发中心": "YF",
  "光敏树脂部": "GMSZ",
  "工程技术部": "GCJS",
  "供应链管理部": "GYLG",
  "计划与控制部": "JHKZ",
  "营销中心": "YX",
  "苏州工厂": "SZGC",
  "南通科德": "NTKD",
  "苏州诺思": "SZNS",
  "K+": "KPLUS",
  "PMC": "PMC",
  "仓库": "CK",
  "其他": "QT",
  "包装": "BZ",
  "品质部": "PZ",
  "公共设备": "GG",
  "仓储物流部": "CCWL",
  "成品包装课": "CPBZ",
  "生产部": "SC",
  "设备部": "SB",
  "行政部": "XZ",
  "仓储部": "CC",
  "品质": "PZ",
  "技术部": "JS",
  "采购部": "CG",
  "基础材料生产部": "JCSC",
  "材料成型及包装部": "CLXJBZ",
  "树脂生产课": "SZSC",
  "高性能材料成型课": "GXXCX",
  "光敏树脂组": "GMSZ",
  "创新组": "CX",
  "医用材料组": "YYCL",
  "实验室": "SY",
  "工艺组": "GY",
  "材料开发组": "CLKF",
  "测试应用组": "CSYY",
  "颜色开发组": "YSKF",
  "Amazon": "AMZ",
  "品牌设计组": "PPSJ",
  "国内业务部": "GN",
  "国内大客户": "GNDKH",
  "国内电商": "GDS",
  "新媒体运营组": "XMTY",
  "海外业务部": "HW",
  "海外大客户": "HWDKH",
  "NPI项目组": "NPI",
  "包装部": "BZ",
  "流程管理组": "LCGL",
  "IT部": "IT",
  "品质管理部": "PZGL",
  "基础材料成型课": "JCCX",
  "生产一班": "SCYB",
  "生产二班": "SCEB",
  "Kexcelled": "KEX",
  "justMaker": "JM",
  "包装8组": "BZ8",
  "包装二组": "BZE",
};

const chineseInitialFallbacks = {
  产: "C", 人: "R", 事: "S", 行: "X", 政: "Z", 研: "Y", 发: "F", 光: "G", 敏: "M", 树: "S",
  脂: "Z", 部: "B", 工: "G", 程: "C", 技: "J", 术: "S", 供: "G", 应: "Y", 链: "L", 管: "G", 理: "L",
  计: "J", 划: "H", 控: "K", 制: "Z", 营: "Y", 销: "X", 心: "X", 苏: "S", 州: "Z", 南: "N", 通: "T",
  科: "K", 德: "D", 产: "C", 品: "P", 财: "C", 务: "W", 仓: "C", 储: "C", 物: "W", 公: "G", 共: "G",
  其: "Q", 他: "T", 成: "C", 包: "B", 装: "Z", 质: "Z", 设: "S", 备: "B", 研: "Y", 采: "C", 购: "G",
  基: "J", 础: "C", 材: "C", 料: "L", 型: "X", 及: "J", 高: "G", 性: "X", 能: "N", 课: "K", 创: "C",
  新: "X", 医: "Y", 用: "Y", 实: "S", 验: "Y", 室: "S", 艺: "Y", 测: "C", 试: "S", 颜: "Y", 色: "S",
  海: "H", 外: "W", 国: "G", 内: "N", 大: "D", 客: "K", 户: "H", 媒: "M", 体: "T", 运: "Y", 项: "X",
  目: "M", 稽: "J", 核: "H", 审: "S", 持: "C", 续: "X", 善: "S", 与: "Y", 组: "Z", 一: "Y", 二: "E",
  班: "B",
};

function chineseInitial(char) {
  return chineseInitialFallbacks[char] || "";
}

function orgCodeBase(name) {
  const text = String(name || "").trim();
  if (!text) return "ORG";
  if (orgCodeOverrides[text]) return orgCodeOverrides[text];
  const ascii = text
    .replace(/[^A-Za-z0-9]+/g, "")
    .toUpperCase();
  if (ascii) return ascii.slice(0, 8);
  const initials = [...text].map(chineseInitial).join("");
  return (initials || "ORG").slice(0, 8);
}

function orgCodeFor(org, parentId = org?.parentId || "", excludeId = org?.id || "") {
  const base = orgCodeBase(org?.name);
  const siblingCodes = new Set(
    state.orgs
      .filter((item) => item.id !== excludeId && (item.parentId || "") === (parentId || ""))
      .map((item) => String(item.code || "").toUpperCase()),
  );
  if (!siblingCodes.has(base)) return base;
  let index = 2;
  while (siblingCodes.has(`${base}${index}`)) index += 1;
  return `${base}${index}`;
}

function employeeNumberPrefix(orgId) {
  const path = [];
  let current = getOrg(orgId);
  const visited = new Set();
  while (current && !visited.has(current.id)) {
    visited.add(current.id);
    path.unshift(current.code || orgCodeBase(current.name));
    current = current.parentId ? getOrg(current.parentId) : null;
  }
  const codes = path.filter(Boolean);
  if (codes[0] === "KPLUS") codes.shift();
  return codes.join("-") || "ORG";
}

function employeeNumberFor(orgId, employeeId = "") {
  const prefix = employeeNumberPrefix(orgId);
  const departmentEmployees = state.employees.filter(
    (employee) => employee.orgId === orgId && employee.id !== employeeId,
  );
  const used = new Set(
    departmentEmployees
      .map((employee) => String(employee.employeeNo || "").match(/-(\d+)$/)?.[1])
      .filter(Boolean)
      .map((value) => Number(value)),
  );
  let sequence = 1;
  while (used.has(sequence)) sequence += 1;
  return `${prefix}-${String(sequence).padStart(3, "0")}`;
}

function cookieValue(name) {
  return document.cookie
    .split(";")
    .map((item) => item.trim())
    .find((item) => item.startsWith(`${name}=`))
    ?.slice(name.length + 1) || "";
}

function requestJson(url, options = {}) {
  const method = String(options.method || "GET").toUpperCase();
  const headers = {
    "Content-Type": "application/json",
    ...(options.headers || {}),
  };
  if (!["GET", "HEAD", "OPTIONS"].includes(method)) {
    const csrfToken = cookieValue("oa_csrf");
    if (csrfToken) headers["X-CSRF-Token"] = csrfToken;
  }
  return fetch(url, {
    ...options,
    method,
    headers,
    credentials: "same-origin",
  }).then(async (response) => {
    const text = await response.text();
    let payload = {};
    try {
      payload = text ? JSON.parse(text) : {};
    } catch (error) {
      const parseError = new Error(`服务器返回了无效响应（${response.status}）`);
      parseError.status = response.status;
      throw parseError;
    }
    if (!response.ok) {
      const error = new Error(payload.error || `Request failed with status ${response.status}`);
      error.status = response.status;
      error.code = payload.code || "";
      if (
        response.status === 401 &&
        authState.authenticated &&
        !url.includes("/api/auth/session") &&
        !url.includes("/api/auth/logout")
      ) {
        authState = { authenticated: false, user: null, bootstrapRequired: false };
        settingsState = {
          settings: {},
          users: [],
          backups: [],
          loaded: false,
          updateStatus: null,
          updateChecking: false,
        };
        authBootPromise = null;
        startAuth();
      }
      throw error;
    }
    return payload;
  });
}

async function requestDownload(url, body = {}) {
  const csrfToken = cookieValue("oa_csrf");
  const response = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(csrfToken ? { "X-CSRF-Token": csrfToken } : {}),
    },
    body: JSON.stringify(body),
    credentials: "same-origin",
  });
  if (!response.ok) {
    const text = await response.text();
    let payload = {};
    try {
      payload = text ? JSON.parse(text) : {};
    } catch (error) {
      payload = {};
    }
    const requestError = new Error(payload.error || `下载失败（${response.status}）`);
    requestError.status = response.status;
    requestError.code = payload.code || "";
    throw requestError;
  }
  const blob = await response.blob();
  const disposition = response.headers.get("Content-Disposition") || "";
  const filenameMatch = disposition.match(/filename="([^"]+)"/i);
  const filename = filenameMatch?.[1] || "database-backup.sql.gz";
  const objectUrl = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = objectUrl;
  anchor.download = filename;
  anchor.style.display = "none";
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  window.setTimeout(() => URL.revokeObjectURL(objectUrl), 1000);
  return filename;
}

async function requestFormData(url, formData, options = {}) {
  const method = String(options.method || "POST").toUpperCase();
  const csrfToken = cookieValue("oa_csrf");
  const headers = {
    ...(csrfToken ? { "X-CSRF-Token": csrfToken } : {}),
    ...(options.headers || {}),
  };
  const response = await fetch(url, {
    ...options,
    method,
    headers,
    body: formData,
    credentials: "same-origin",
  });
  const text = await response.text();
  let payload = {};
  try {
    payload = text ? JSON.parse(text) : {};
  } catch (error) {
    const parseError = new Error(`服务器返回了无效响应（${response.status}）`);
    parseError.status = response.status;
    throw parseError;
  }
  if (!response.ok) {
    const requestError = new Error(payload.error || `Request failed with status ${response.status}`);
    requestError.status = response.status;
    requestError.code = payload.code || "";
    throw requestError;
  }
  return payload;
}

function renderAuthScreen(errorMessage = "") {
  const root = document.querySelector("#authRoot");
  const appShell = document.querySelector("#appShell");
  if (!root || !appShell) return;
  appShell.hidden = true;
  root.hidden = false;
  const appName = settingsState.settings.app_name || "办公资产管理系统";
  const loginNotice = settingsState.settings.login_notice || "";
  const bootstrap = Boolean(authState.bootstrapRequired);
  const form = bootstrap
    ? `<form class="auth-form" data-form="auth-bootstrap">
        ${inputField("管理员账号", "username", "", true, "请输入 3-64 位账号", "text", "", 'autocomplete="username"')}
        ${inputField("显示名称", "displayName", "", true, "例如：IT 管理员")}
        ${inputField("登录密码", "password", "", true, "至少 8 位", "password", "8", 'autocomplete="new-password"')}
        ${inputField("确认密码", "confirmPassword", "", true, "再次输入密码", "password", "8", 'autocomplete="new-password"')}
        <button class="primary-button auth-submit" type="submit">创建管理员并进入系统</button>
      </form>`
    : `<form class="auth-form" data-form="auth-login">
        ${inputField("账号", "username", "", true, "请输入账号", "text", "", 'autocomplete="username"')}
        ${inputField("密码", "password", "", true, "请输入密码", "password", "", 'autocomplete="current-password"')}
        <button class="primary-button auth-submit" type="submit">登录系统</button>
      </form>`;
  root.innerHTML = `
    <main class="auth-page">
      <section class="auth-panel">
        <div class="auth-brand">
          <span class="brand-mark">OA</span>
          <div><strong>${escapeHtml(appName)}</strong><span>办公资产运营平台</span></div>
        </div>
        <div class="auth-heading">
          <span class="eyebrow">${bootstrap ? "FIRST RUN SETUP" : "SECURE SIGN IN"}</span>
          <h1>${bootstrap ? "初始化管理员账号" : "登录系统"}</h1>
          <p>${bootstrap ? "首次使用请创建一名管理员，之后可在设置中维护其他账号。" : "请输入账号和密码继续使用资产管理系统。"}</p>
        </div>
        ${errorMessage ? `<div class="auth-error">${escapeHtml(errorMessage)}</div>` : ""}
        ${loginNotice ? `<div class="auth-notice">${escapeHtml(loginNotice)}</div>` : ""}
        ${form}
        <div class="auth-footer">MySQL 联机模式 · 会话由服务器安全管理</div>
      </section>
    </main>`;
}

function updateAuthenticatedChrome() {
  const appShell = document.querySelector("#appShell");
  const root = document.querySelector("#authRoot");
  if (!appShell || !root) return;
  appShell.hidden = !authState.authenticated;
  root.hidden = authState.authenticated;
  if (!authState.authenticated) return;
  const user = authState.user || {};
  const displayName = user.displayName || user.username || "未登录";
  const initials = [...displayName.replace(/\s+/g, "")].slice(0, 2).join("") || "IT";
  const avatar = document.querySelector("#userAvatar");
  const badge = document.querySelector("#userBadgeText");
  const brandName = document.querySelector("#brandName");
  const brandSubtitle = document.querySelector("#brandSubtitle");
  if (avatar) avatar.textContent = initials;
  if (badge) {
    badge.innerHTML = `<strong>${escapeHtml(displayName)}</strong><small>${escapeHtml(
      `${user.username || ""} · ${authRoleLabel(user.role)}`,
    )}</small>`;
  }
  if (brandName) brandName.textContent = settingsState.settings.app_name || "办公资产";
  if (brandSubtitle) brandSubtitle.textContent = "管理中台";
  appShell.classList.toggle("is-read-only", !canWriteState());
}

async function loadSettingsState(options = {}) {
  const settingsPayload = await requestJson(API_SETTINGS_URL);
  settingsState.settings = settingsPayload.settings || {};
  if (options.users && isAdminUser()) {
    const usersPayload = await requestJson(API_USERS_URL);
    settingsState.users = Array.isArray(usersPayload.users) ? usersPayload.users : [];
  }
  if (isAdminUser()) {
    const backupsPayload = await requestJson(API_BACKUPS_URL);
    settingsState.backups = Array.isArray(backupsPayload.backups) ? backupsPayload.backups : [];
  } else {
    settingsState.backups = [];
  }
  settingsState.loaded = true;
  updateAuthenticatedChrome();
  return settingsState;
}

async function enterAuthenticatedSession(payload) {
  authState = {
    authenticated: true,
    user: payload.user || null,
    bootstrapRequired: false,
  };
  updateAuthenticatedChrome();
  try {
    await loadSettingsState({ users: isAdminUser() });
  } catch (error) {
    console.error("Unable to load authenticated settings", error);
  }
  await hydrateStateFromServer({ toast: false });
  render();
}

async function startAuth() {
  if (authBootPromise) return authBootPromise;
  authBootPromise = (async () => {
    try {
      const session = await requestJson(API_AUTH_SESSION_URL);
      if (session.authenticated) {
        await enterAuthenticatedSession(session);
        return;
      }
    } catch (error) {
      if (error.status !== 401) {
        renderAuthScreen(`连接认证服务失败：${error.message}`);
        return;
      }
    }
    try {
      const status = await requestJson(API_AUTH_BOOTSTRAP_STATUS_URL);
      settingsState.settings = status.settings || settingsState.settings;
      authState = { authenticated: false, user: null, bootstrapRequired: Boolean(status.required) };
      renderAuthScreen();
    } catch (error) {
      renderAuthScreen(`无法读取登录状态：${error.message}`);
    }
  })();
  return authBootPromise;
}

async function handleAuthSubmit(form) {
  const data = Object.fromEntries(new FormData(form).entries());
  const isBootstrap = form.dataset.form === "auth-bootstrap";
  const endpoint = isBootstrap ? API_AUTH_BOOTSTRAP_URL : API_AUTH_LOGIN_URL;
  const submit = form.querySelector('button[type="submit"]');
  if (submit) submit.disabled = true;
  try {
    const payload = await requestJson(endpoint, {
      method: "POST",
      body: JSON.stringify(data),
    });
    await enterAuthenticatedSession(payload);
  } catch (error) {
    renderAuthScreen(error.message);
  } finally {
    if (submit) submit.disabled = false;
  }
}

async function logout() {
  try {
    await requestJson(API_AUTH_LOGOUT_URL, { method: "POST", body: "{}" });
  } catch (error) {
    console.error("Unable to log out", error);
  }
  authState = { authenticated: false, user: null, bootstrapRequired: false };
  settingsState = {
    settings: {},
    users: [],
    backups: [],
    loaded: false,
    updateStatus: null,
    updateChecking: false,
  };
  document.querySelector("#modalRoot").innerHTML = "";
  authBootPromise = null;
  startAuth();
}

function applyRemoteState(payload) {
  state = normalizeState({
    ...state,
    ...payload,
  });
  if (!state.expandedOrgIds.length) {
    state.expandedOrgIds = state.orgs.map((org) => org.id);
  }
  syncEmployeeSearchDraftsFromFilters();
}

function buildAuditLogsUrl(limit = 5000) {
  const params = new URLSearchParams();
  const {
    auditStartDate,
    auditEndDate,
    auditEmployee,
    auditAction,
    auditCategory,
    auditEntityType,
    auditSearch,
  } = state.filters;
  if (auditStartDate) params.set("startDate", auditStartDate);
  if (auditEndDate) params.set("endDate", auditEndDate);
  if (auditEmployee) params.set("employee", auditEmployee.trim());
  if (auditAction) params.set("actionType", auditAction);
  if (auditCategory) params.set("category", auditCategory);
  if (auditEntityType) params.set("entityType", auditEntityType);
  if (auditSearch) params.set("keyword", auditSearch.trim());
  params.set("limit", String(limit));
  return `${API_AUDIT_LOGS_URL}?${params.toString()}`;
}

async function refreshAuditLogs(options = {}) {
  const payload = await requestJson(buildAuditLogsUrl(options.limit || 5000));
  state.auditLogs = normalizeState({ auditLogs: payload.logs || [], auditLogTotal: payload.total || 0 }).auditLogs;
  state.auditLogTotal = Math.max(0, Number(payload.total || state.auditLogs.length));
  if (!options.silent) render();
  return payload;
}

function queueAuditLogRefresh() {
  window.clearTimeout(auditFilterRefreshTimer);
  auditFilterRefreshTimer = window.setTimeout(() => {
    refreshAuditLogs({ silent: true })
      .then(() => render())
      .catch((error) => {
        console.error("Unable to load audit logs", error);
        showToast(`日志加载失败：${error.message}`, true);
      });
  }, 220);
}

function persistState(syncRemote = false) {
  window.localStorage.setItem(UI_STORAGE_KEY, JSON.stringify(extractUiState(state)));
  if (!syncRemote) return remoteSyncQueue;

  remoteSyncQueue = remoteSyncQueue
    .catch(() => undefined)
    .then(async () => {
      normalizeComputersAgainstEmployees();
      const payload = await requestJson(API_STATE_URL, {
        method: "PUT",
        body: JSON.stringify(extractDataState(state)),
      });
      applyRemoteState(payload);
      state.auditLogTotal = state.auditLogs.length;
      await refreshAuditLogs({ silent: true });
      window.localStorage.setItem(UI_STORAGE_KEY, JSON.stringify(extractUiState(state)));
      render();
    })
    .catch((error) => {
      console.error("Unable to sync state to database", error);
      if (error.status === 409 || error.code === "STATE_CONFLICT") {
        showToast("数据库数据已被其他页面更新，请刷新后再保存", true);
        hydrateStateFromServer({ toast: false });
        return;
      }
      showToast(`数据库同步失败：${error.message}`, true);
    });

  return remoteSyncQueue;
}

async function hydrateStateFromServer(options = {}) {
  try {
    const payload = await requestJson(API_STATE_URL);
    applyRemoteState(payload);
    state.auditLogTotal = state.auditLogs.length;
    await refreshAuditLogs({ silent: true });
    window.localStorage.setItem(UI_STORAGE_KEY, JSON.stringify(extractUiState(state)));
    render();
    if (options.toast) showToast("已从数据库加载最新数据");
  } catch (error) {
    console.error("Unable to load database state", error);
    if (options.toast !== false) {
      showToast(`数据库加载失败：${error.message}`, true);
    }
  }
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function compareText(a, b) {
  return String(a || "").localeCompare(String(b || ""), "zh-CN");
}

function getOrg(id) {
  return state.orgs.find((org) => org.id === id);
}

function getEmployee(id) {
  return state.employees.find((employee) => employee.id === id);
}

function getLeftEmployee(id) {
  return state.leftEmployees.find((employee) => employee.id === id);
}

function getLeftEmployeeBySource(sourceEmployeeId, employeeNo = "") {
  return state.leftEmployees.find(
    (employee) =>
      (sourceEmployeeId && employee.sourceEmployeeId === sourceEmployeeId) ||
      (employeeNo && employee.employeeNo === employeeNo),
  );
}

function getType(id) {
  return state.nonAssetTypes.find((type) => type.id === id);
}

function isComputerInventoryType(type) {
  const code = inventoryText(type?.code);
  const name = inventoryText(type?.name);
  return code === "computer" || code === "pc" || name === "电脑";
}

function isComputerInventoryTypeName(name) {
  const text = inventoryText(name);
  return text === "电脑" || text === "computer" || text === "pc";
}

function computerInventoryType() {
  return state.nonAssetTypes.find((type) => isComputerInventoryType(type));
}

function computerInventoryTypeId() {
  return computerInventoryType()?.id || "";
}

function isProtectedInventoryType(type) {
  return isComputerInventoryType(type);
}

function defaultMonitorTypeId() {
  const preferred = state.nonAssetTypes.find((type) => {
    const text = `${type.code || ""} ${type.name || ""}`.toLowerCase();
    return text.includes("monitor") || text.includes("display") || text.includes("\u663e\u793a");
  });
  return preferred?.id || state.nonAssetTypes[0]?.id || "mouse";
}

function getInventoryBrand(id) {
  return state.inventoryBrands.find((brand) => brand.id === id);
}

function getInventoryModel(id) {
  return state.inventoryModels.find((model) => model.id === id);
}

function inventoryBrandsForType(typeId) {
  return state.inventoryBrands
    .filter((brand) => brand.typeId === typeId)
    .sort((a, b) => Number(a.sortOrder) - Number(b.sortOrder) || compareText(a.name, b.name));
}

function inventoryModelsForBrand(brandId) {
  return state.inventoryModels
    .filter((model) => model.brandId === brandId)
    .sort((a, b) => Number(a.sortOrder) - Number(b.sortOrder) || compareText(a.name, b.name));
}

function inventoryTypeTotal(typeId) {
  return state.inventoryModels
    .filter((model) => model.typeId === typeId)
    .reduce((sum, model) => sum + Math.max(0, Number(model.quantity || 0)), 0);
}

function inventoryTypeUsageCount(typeId) {
  const assignedCount = state.employees.reduce((sum, employee) => {
    const monitorCount = (employee.monitors || []).filter((item) => item.typeId === typeId).length;
    const nonAssetCount = getNonAssetItems(employee).filter((item) => item.typeId === typeId).length;
    return sum + monitorCount + nonAssetCount;
  }, 0);
  const stockCount =
    state.inventoryBrands.filter((item) => item.typeId === typeId).length +
    state.inventoryModels.filter((item) => item.typeId === typeId).length;
  return assignedCount + stockCount;
}

function inventoryBrandTotal(brandId) {
  return state.inventoryModels
    .filter((model) => model.brandId === brandId)
    .reduce((sum, model) => sum + Math.max(0, Number(model.quantity || 0)), 0);
}

const inventoryTypeCodeOverrides = {
  鼠标: "SB",
  键盘: "JP",
  显示屏: "XSP",
  显示器: "XSQ",
  拓展坞: "TZW",
  耳机: "EJ",
  摄像头: "SXT",
  支架: "ZJ",
  笔记本支架: "BJBZJ",
  电脑支架: "DNZJ",
  USB集线器: "USB",
  电源适配器: "DYSPQ",
  充电器: "CDQ",
  数据线: "SJX",
  电脑: "DN",
};

function inventoryCodeBase(name) {
  const text = String(name || "").trim();
  if (!text) return "IT";
  if (inventoryTypeCodeOverrides[text]) return inventoryTypeCodeOverrides[text];
  const ascii = text.replace(/[^A-Za-z0-9]+/g, "").toUpperCase();
  if (ascii) return ascii.slice(0, 8);
  const initials = [...text].map(chineseInitial).join("");
  return (initials || "IT").slice(0, 8);
}

function inventoryTypeCodeFor(name, excludeId = "") {
  const base = inventoryCodeBase(name);
  const siblingCodes = new Set(
    state.nonAssetTypes
      .filter((item) => item.id !== excludeId)
      .map((item) => String(item.code || "").toUpperCase()),
  );
  if (!siblingCodes.has(base)) return base;
  let index = 2;
  while (siblingCodes.has(`${base}${index}`)) index += 1;
  return `${base}${index}`;
}

function nextTypeSortOrder() {
  return state.nonAssetTypes.reduce((max, item) => Math.max(max, Number(item.sortOrder || 0)), 0) + 10;
}

function nextBrandSortOrder(typeId) {
  return state.inventoryBrands
    .filter((item) => item.typeId === typeId)
    .reduce((max, item) => Math.max(max, Number(item.sortOrder || 0)), 0) + 10;
}

function nextModelSortOrder(brandId) {
  return state.inventoryModels
    .filter((item) => item.brandId === brandId)
    .reduce((max, item) => Math.max(max, Number(item.sortOrder || 0)), 0) + 10;
}

function inventoryText(value) {
  return String(value || "").trim().toLowerCase();
}

function inventoryTypeSearchText(type) {
  return inventoryText([type.code, type.name, type.unit].filter(Boolean).join(" "));
}

function inventoryBrandSearchText(brand) {
  return inventoryText(brand.name);
}

function inventoryModelSearchText(model) {
  return inventoryText(
    [
      model.name,
      model.batchKey,
      model.quantity,
      model.inboundDate,
      model.cpu,
      model.memory,
      model.storage,
      model.gpu,
    ]
      .filter((value) => value !== "" && value !== null && value !== undefined)
      .join(" "),
  );
}

function inventoryModelConfigSummary(model) {
  return [
    ["CPU", model.cpu],
    ["内存", model.memory],
    ["存储", model.storage],
    ["显卡", model.gpu],
  ]
    .filter(([, value]) => String(value || "").trim())
    .map(([label, value]) => `${label}: ${value}`)
    .join(" / ");
}

function inventoryModelDisplayMeta(type, model) {
  return [
    `${Math.max(0, Number(model.quantity || 0))} ${type?.unit || "件"}`,
    isComputerInventoryType(type) && model.inboundDate ? `入库：${model.inboundDate}` : "",
    isComputerInventoryType(type) ? inventoryModelConfigSummary(model) : "",
  ]
    .filter(Boolean)
    .join(" / ");
}

function inventoryModelOptionLabel(model) {
  const parts = [`${model.name} (${Math.max(0, Number(model.quantity || 0))})`];
  if (isComputerInventoryType(getType(model.typeId)) && model.inboundDate) {
    parts.push(`入库：${model.inboundDate}`);
  }
  const config = inventoryModelConfigSummary(model);
  if (config) parts.push(config);
  return parts.join(" · ");
}

function normalizeStorageValue(value) {
  const text = String(value || "").trim();
  return /^500\s*g(?:b)?$/i.test(text) ? "512G" : text;
}

function currentTimestampText() {
  const now = new Date();
  const pad = (value) => String(value).padStart(2, "0");
  return `${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())} ${pad(now.getHours())}:${pad(
    now.getMinutes(),
  )}:${pad(now.getSeconds())}`;
}

function currentDateText() {
  return currentTimestampText().slice(0, 10);
}

function normalizeInventoryMovementLogs(logs) {
  return (Array.isArray(logs) ? logs : []).map((log) => ({
    id: String(log.id || createId("invlog")),
    direction: log.direction === "decrease" ? "decrease" : "increase",
    typeName: log.typeName || "",
    brandName: log.brandName || "",
    modelName: log.modelName || "",
    quantity: Math.max(1, Number(log.quantity || 1)),
    sourceLabel: log.sourceLabel || "",
    targetLabel: log.targetLabel || "",
    note: log.note || "",
    relatedEmployeeNo: log.relatedEmployeeNo || "",
    relatedEmployeeName: log.relatedEmployeeName || "",
    triggerAction: log.triggerAction || "manual",
    occurredAt: log.occurredAt || "",
  }));
}

function normalizeInventoryPurchaseLogs(logs) {
  return (Array.isArray(logs) ? logs : []).map((log) => ({
    id: String(log.id || createId("purchase")),
    typeName: log.typeName || "",
    brandName: log.brandName || "",
    modelName: log.modelName || "",
    typeId: String(log.typeId || ""),
    brandId: String(log.brandId || ""),
    modelId: String(log.modelId || ""),
    quantity: Math.max(1, Number(log.quantity || 1)),
    inboundDate: log.inboundDate || "",
    cpu: log.cpu || "",
    memory: log.memory || "",
    storage: log.storage || "",
    gpu: log.gpu || "",
    sourceLabel: log.sourceLabel || "",
    note: log.note || "",
    sourceMovementLogId: log.sourceMovementLogId || "",
    createdAt: log.createdAt || "",
  }));
}

function inventoryDirectionLabel(direction) {
  return direction === "decrease" ? "减少" : "增加";
}

function inventoryDirectionClass(direction) {
  return direction === "decrease" ? "audit-action-alert" : "audit-action-added";
}

function inventoryMovementParticipants(sourceLabel, targetLabel) {
  return `${sourceLabel || "—"} → ${targetLabel || "—"}`;
}

function upsertInventoryMovementLog(entry) {
  const item = {
    id: String(entry.id || createId("invlog")),
    direction: entry.direction === "decrease" ? "decrease" : "increase",
    typeName: entry.typeName || "",
    brandName: entry.brandName || "",
    modelName: entry.modelName || "",
    quantity: Math.max(1, Number(entry.quantity || 1)),
    sourceLabel: entry.sourceLabel || "",
    targetLabel: entry.targetLabel || "",
    note: entry.note || "",
    relatedEmployeeNo: entry.relatedEmployeeNo || "",
    relatedEmployeeName: entry.relatedEmployeeName || "",
    triggerAction: entry.triggerAction || "manual",
    occurredAt: entry.occurredAt || currentTimestampText(),
  };
  const index = state.inventoryMovementLogs.findIndex((log) => log.id === item.id);
  if (index >= 0) state.inventoryMovementLogs[index] = item;
  else state.inventoryMovementLogs.unshift(item);
  return item;
}

function employeeLogLabel(employeeNo = "", employeeName = "") {
  if (employeeName && employeeNo) return `${employeeName} (${employeeNo})`;
  return employeeName || employeeNo || "人员";
}

function modelLogNames(model) {
  if (!model) return { typeName: "", brandName: "", modelName: "" };
  const brand = getInventoryBrand(model.brandId);
  const type = getType(model.typeId);
  return {
    typeName: type?.name || "",
    brandName: brand?.name || "",
    modelName: model.name || "",
  };
}

function recordInventoryMovement(entry) {
  return upsertInventoryMovementLog({
    direction: entry.direction,
    typeName: entry.typeName,
    brandName: entry.brandName,
    modelName: entry.modelName,
    quantity: entry.quantity,
    sourceLabel: entry.sourceLabel,
    targetLabel: entry.targetLabel,
    note: entry.note || "",
    relatedEmployeeNo: entry.relatedEmployeeNo || "",
    relatedEmployeeName: entry.relatedEmployeeName || "",
    triggerAction: entry.triggerAction || "manual",
    occurredAt: entry.occurredAt || currentTimestampText(),
  });
}

function getInventoryFilterContext() {
  const search = inventoryText(state.filters.inventorySearch);
  const typeId = state.filters.inventoryType || "";
  const brandId = state.filters.inventoryBrand || "";
  const selectedBrand = brandId ? getInventoryBrand(brandId) : null;
  return { search, typeId, brandId, selectedBrand };
}

function inventoryTypeFilterOptions() {
  return [{ value: "", label: "全部类型" }].concat(
    state.nonAssetTypes.map((type) => ({ value: type.id, label: type.name })),
  );
}

function inventoryBrandFilterOptions(typeId = "") {
  const brands = typeId ? inventoryBrandsForType(typeId) : [...state.inventoryBrands].sort((a, b) => compareText(a.name, b.name));
  return [{ value: "", label: "全部品牌" }].concat(brands.map((brand) => ({ value: brand.id, label: brand.name })));
}

function buildInventoryTreeNodes() {
  const { search, typeId, brandId, selectedBrand } = getInventoryFilterContext();

  return state.nonAssetTypes
    .filter((type) => {
      if (typeId && type.id !== typeId) return false;
      if (selectedBrand && selectedBrand.typeId !== type.id) return false;
      return true;
    })
    .map((type) => {
      const brands = inventoryBrandsForType(type.id)
        .filter((brand) => {
          if (brandId && brand.id !== brandId) return false;
          return true;
        })
        .map((brand) => {
          const models = inventoryModelsForBrand(brand.id).filter((model) => {
            if (!search) return true;
            return inventoryModelSearchText(model).includes(search);
          });
          const brandVisible =
            !search ||
            brandId === brand.id ||
            inventoryBrandSearchText(brand).includes(search) ||
            models.length > 0;
          return brandVisible ? { ...brand, models } : null;
        })
        .filter(Boolean);

      const typeVisible =
        !search ||
        inventoryTypeSearchText(type).includes(search) ||
        brands.length > 0 ||
        typeId === type.id ||
        (selectedBrand && selectedBrand.typeId === type.id);

      return typeVisible ? { type, brands } : null;
    })
    .filter(Boolean);
}

function inventoryFlatRows() {
  return buildInventoryTreeNodes().flatMap(({ type, brands }) =>
    brands.flatMap((brand) =>
      brand.models.map((model) => ({
        type,
        brand,
        model,
      })),
    ),
  );
}

function inventoryModelForSelection(typeId, brandId, modelName) {
  return state.inventoryModels.find(
    (model) => model.typeId === typeId && model.brandId === brandId && model.name === modelName,
  );
}

function resolveInventorySelection(data) {
  const typeId = data.typeId || "";
  const selectedBrand = data.brandId && data.brandId !== "__custom__" ? getInventoryBrand(data.brandId) : null;
  const brand = String(selectedBrand?.name || data.brandCustom || data.brand || "").trim();
  const selectedModel = data.modelId && data.modelId !== "__custom__" ? getInventoryModel(data.modelId) : null;
  const model = String(selectedModel?.name || data.modelCustom || data.model || "").trim();
  const brandId = selectedBrand?.typeId === typeId ? selectedBrand.id : "";
  const modelId =
    selectedModel?.typeId === typeId && selectedModel?.brandId === brandId ? selectedModel.id : "";
  return { typeId, brand, model, inventoryBrandId: brandId, inventoryModelId: modelId };
}

function replaceSelectOptions(select, options, selectedValue = "__custom__") {
  if (!select) return;
  select.innerHTML = options
    .map(
      (option) =>
        `<option value="${escapeHtml(option.value)}" ${
          String(option.value) === String(selectedValue) ? "selected" : ""
        }>${escapeHtml(option.label)}</option>`,
    )
    .join("");
}

function updateNonAssetModuleSummary(form) {
  if (!form || form.dataset.form !== "nonasset") return;
  const summary = form.querySelector(".device-module-header strong");
  if (!summary) return;
  const type = getType(form.elements.typeId?.value || "");
  summary.textContent = type?.name || "非资产设备";
}

function updateDeviceInventorySelectors(form, changedField) {
  const typeId = form.elements.typeId?.value || "";
  const brandSelect = form.elements.brandId;
  const modelSelect = form.elements.modelId;
  const brandCustom = form.elements.brandCustom;
  const modelCustom = form.elements.modelCustom;
  if (changedField === "typeId") {
    replaceSelectOptions(
      brandSelect,
      [{ value: "__custom__", label: "自定义品牌" }].concat(
        inventoryBrandsForType(typeId).map((brand) => ({ value: brand.id, label: brand.name })),
      ),
    );
    replaceSelectOptions(modelSelect, [{ value: "__custom__", label: "自定义型号" }]);
    if (brandCustom) brandCustom.value = "";
    if (modelCustom) modelCustom.value = "";
    updateNonAssetModuleSummary(form);
    return;
  }
  const brandId = brandSelect?.value && brandSelect.value !== "__custom__" ? brandSelect.value : "";
  if (changedField === "brandId") {
    replaceSelectOptions(
      modelSelect,
      [{ value: "__custom__", label: "自定义型号" }].concat(
        inventoryModelsForBrand(brandId).map((model) => ({
          value: model.id,
          label: inventoryModelOptionLabel(model),
        })),
      ),
    );
    if (brandId && brandCustom) brandCustom.value = "";
    if (modelCustom) modelCustom.value = "";
  }
  if (changedField === "modelId" && modelSelect?.value !== "__custom__" && modelCustom) {
    modelCustom.value = "";
  }
}

function getNonAssetItems(employee) {
  if (Array.isArray(employee?.nonAssetItems)) return employee.nonAssetItems;
  return Object.entries(employee?.nonAssets || {}).reduce((items, [typeId, quantity]) => {
    const count = Math.max(0, Number(quantity || 0));
    if (count) {
      items.push({ id: createId("na"), typeId, brand: "", model: "", quantity: count });
    }
    return items;
  }, []);
}

function syncNonAssetAggregate(employee) {
  employee.nonAssets = getNonAssetItems(employee).reduce((aggregate, item) => {
    const quantity = Math.max(0, Number(item.quantity || 0));
    if (quantity) aggregate[item.typeId] = (aggregate[item.typeId] || 0) + quantity;
    return aggregate;
  }, {});
  return employee.nonAssets;
}

function normalizeMacAddress(value) {
  const raw = String(value || "").trim();
  if (!raw) return "";
  const colonFormat = /^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$/i.test(raw);
  const hyphenFormat = /^(?:[0-9a-f]{2}-){5}[0-9a-f]{2}$/i.test(raw);
  if (!colonFormat && !hyphenFormat) return raw;
  const compact = raw.replaceAll(":", "").replaceAll("-", "").toUpperCase();
  return compact.match(/../g).join("-");
}

function isValidMacAddress(value) {
  return !value || /^(?:[0-9A-F]{2}-){5}[0-9A-F]{2}$/.test(String(value).trim());
}

function normalizeComputerRecord(computer, validEmployeeIds = null) {
  const normalized = {
    id: computer.id || createId("pc"),
    deviceName: computer.deviceName || "",
    orgId: computer.orgId || "",
    deviceType: computer.deviceType || "laptop",
    brand: computer.brand || "",
    model: computer.model || "",
    inventoryModelId: computer.inventoryModelId ? String(computer.inventoryModelId) : "",
    inventoryStockAdjusted: Boolean(computer.inventoryStockAdjusted),
    cpu: computer.cpu || "",
    memory: computer.memory || "",
    storage: computer.storage || "",
    gpu: computer.gpu || "",
    fixedAssetCode: computer.fixedAssetCode || "",
    purchaseDate: computer.purchaseDate || "",
    registeredDate: computer.registeredDate || "",
    snSt: computer.snSt || "",
    wifiMac: normalizeMacAddress(computer.wifiMac),
    ethernetMac: normalizeMacAddress(computer.ethernetMac),
    location: computer.location || "",
    department: computer.department || "",
    status: computer.status || "idle",
    userId: computer.userId ? String(computer.userId) : null,
    remarks: computer.remarks || "",
  };

  if (validEmployeeIds instanceof Set && normalized.userId && !validEmployeeIds.has(normalized.userId)) {
    normalized.userId = null;
  }

  if (["repair", "retired", "lost"].includes(normalized.status)) {
    normalized.userId = null;
  }

  if (normalized.userId) {
    normalized.status = "in_use";
  } else if (normalized.status === "in_use") {
    normalized.status = "idle";
  }

  return normalized;
}

function normalizeComputersAgainstEmployees() {
  const employeeIds = new Set(state.employees.map((employee) => employee.id));
  state.computers = state.computers.map((computer) => normalizeComputerRecord(computer, employeeIds));
}

function getCurrentUser(computer) {
  return computer.userId ? getEmployee(computer.userId) : null;
}

function orgName(id) {
  return getOrg(id)?.name || "未分配组织";
}

function orgPathName(id) {
  const path = [];
  let current = getOrg(id);
  const visited = new Set();
  while (current && !visited.has(current.id)) {
    visited.add(current.id);
    path.unshift(current.name);
    current = current.parentId ? getOrg(current.parentId) : null;
  }
  return path.length ? path.join(" / ") : "未分配组织";
}

function statusPill(status) {
  const safeStatus = status || "idle";
  return `<span class="status-pill status-${escapeHtml(safeStatus)}">${escapeHtml(
    statusLabels[safeStatus] || safeStatus,
  )}</span>`;
}

function formatDate(value) {
  if (!value) return "—";
  return value.replaceAll("-", ".");
}

function formatDateTime(value) {
  if (!value) return "—";
  return String(value).replace("T", " ").slice(0, 19);
}

function deviceTypeLabel(value) {
  return deviceTypeLabels[value] || value || "—";
}

function computerConfigSummary(computer) {
  return [
    ["CPU", computer.cpu],
    ["内存", computer.memory],
    ["存储", computer.storage],
    ["显卡", computer.gpu],
  ]
    .filter(([, value]) => String(value || "").trim())
    .map(([label, value]) => `${label}: ${value}`)
    .join(" / ");
}

function deviceTypeTag(value) {
  return `<span class="tag-chip">${escapeHtml(deviceTypeLabel(value))}</span>`;
}

function orgSortKey(org) {
  return `${String(org.sortOrder).padStart(6, "0")}-${org.code}-${org.name}`;
}

function isRootOrg(org) {
  return !org.parentId || !getOrg(org.parentId);
}

function getOrgChildren(parentId) {
  return [...state.orgs]
    .filter((org) => (org.parentId || "") === (parentId || ""))
    .sort((a, b) => orgSortKey(a).localeCompare(orgSortKey(b), "en"));
}

function getRootOrgs() {
  return [...state.orgs]
    .filter((org) => isRootOrg(org))
    .sort((a, b) => orgSortKey(a).localeCompare(orgSortKey(b), "en"));
}

function getOrgDepth(orgId) {
  let depth = 0;
  let current = getOrg(orgId);
  const visited = new Set();
  while (current?.parentId && !visited.has(current.id)) {
    visited.add(current.id);
    depth += 1;
    current = getOrg(current.parentId);
  }
  return depth;
}

function getDescendantOrgIds(orgId, visited = new Set()) {
  const descendants = [];
  if (visited.has(orgId)) return descendants;
  visited.add(orgId);
  getOrgChildren(orgId).forEach((child) => {
    descendants.push(child.id);
    descendants.push(...getDescendantOrgIds(child.id, visited));
  });
  return descendants;
}

function getSubtreeOrgIds(orgId) {
  return [orgId].concat(getDescendantOrgIds(orgId));
}

function sortEmployees(employees) {
  return [...employees].sort((a, b) => {
    const noCompare = compareText(a.employeeNo, b.employeeNo);
    return noCompare || compareText(a.name, b.name);
  });
}

function getFilteredComputers() {
  const search = (state.filters.computers || "").trim().toLowerCase();
  const statusFilter = state.filters.computerStatus || "";

  return state.computers.filter((computer) => {
    const user = getCurrentUser(computer);
    const searchText = [
      computer.deviceName,
      computer.brand,
      computer.model,
      computer.cpu,
      computer.memory,
      computer.storage,
      computer.gpu,
      computer.fixedAssetCode,
      computer.snSt,
      orgPathName(computer.orgId),
      user?.name,
    ]
      .join(" ")
      .toLowerCase();
    return (!search || searchText.includes(search)) && (!statusFilter || computer.status === statusFilter);
  });
}

function getFilteredEmployees() {
  const search = (state.filters.employees || "").trim().toLowerCase();
  const assetSearch = (state.filters.employeeAssetSearch || "").trim().toLowerCase();
  const statusFilter = state.filters.employeeStatus || "";
  const orgFilter = state.filters.employeeOrg || "";
  const deviceFilter = state.filters.employeeDevice || "";
  const orgScope =
    orgFilter && orgFilter !== "__unassigned__" ? new Set(getSubtreeOrgIds(orgFilter)) : null;

  return sortEmployees(
    state.employees.filter((employee) => {
      const assignedDevices = employeeDevices(employee);
      const searchText = [
        employee.employeeNo,
        employee.name,
        employee.department,
        employee.position,
        orgPathName(employee.orgId),
      ]
        .join(" ")
        .toLowerCase();
      const deviceSearchText = assignedDevices
        .flatMap((device) => [device.label, device.detail, device.brand, device.model])
        .filter(Boolean)
        .join(" ")
        .toLowerCase();
      const matchesOrg =
        !orgFilter ||
        (orgFilter === "__unassigned__"
          ? !employee.orgId || !getOrg(employee.orgId)
          : orgScope?.has(employee.orgId || ""));
      const hasDevices = assignedDevices.length > 0;
      const matchesDevice =
        !deviceFilter ||
        (deviceFilter === "assigned" && hasDevices) ||
        (deviceFilter === "unassigned" && !hasDevices);
      return (
        (!search || searchText.includes(search)) &&
        (!assetSearch || deviceSearchText.includes(assetSearch)) &&
        (!statusFilter || employee.status === statusFilter) &&
        matchesOrg &&
        matchesDevice
      );
    }),
  );
}

function getOrgEmployeeCount(orgId, includeDescendants = false) {
  const scope = new Set(includeDescendants ? getSubtreeOrgIds(orgId) : [orgId]);
  return state.employees.filter((employee) => scope.has(employee.orgId || "")).length;
}

function getOrgComputerCount(orgId, includeDescendants = false) {
  const scope = new Set(includeDescendants ? getSubtreeOrgIds(orgId) : [orgId]);
  return state.computers.filter((computer) => scope.has(computer.orgId || "")).length;
}

function getOrgSummary(orgId) {
  return {
    employees: getOrgEmployeeCount(orgId, true),
    computers: getOrgComputerCount(orgId, true),
    children: getDescendantOrgIds(orgId).length,
  };
}

function isOrgExpanded(orgId) {
  return state.expandedOrgIds.includes(orgId);
}

function setOrgExpanded(orgId, expanded) {
  const current = new Set(state.expandedOrgIds);
  if (expanded) current.add(orgId);
  else current.delete(orgId);
  state.expandedOrgIds = [...current];
  persistState(false);
}

function ensureOrgExpanded(orgId) {
  if (!orgId) return;
  const ancestors = [];
  let current = getOrg(orgId);
  const visited = new Set();
  while (current && !visited.has(current.id)) {
    visited.add(current.id);
    ancestors.push(current.id);
    current = current.parentId ? getOrg(current.parentId) : null;
  }
  state.expandedOrgIds = [...new Set(state.expandedOrgIds.concat(ancestors))];
}

function isInventoryTypeExpanded(typeId) {
  return state.expandedInventoryTypeIds.includes(typeId);
}

function setInventoryTypeExpanded(typeId, expanded) {
  const current = new Set(state.expandedInventoryTypeIds);
  if (expanded) current.add(typeId);
  else current.delete(typeId);
  state.expandedInventoryTypeIds = [...current];
  persistState(false);
}

function isInventoryBrandExpanded(brandId) {
  return state.expandedInventoryBrandIds.includes(brandId);
}

function setInventoryBrandExpanded(brandId, expanded) {
  const current = new Set(state.expandedInventoryBrandIds);
  if (expanded) current.add(brandId);
  else current.delete(brandId);
  state.expandedInventoryBrandIds = [...current];
  persistState(false);
}

function ensureInventoryExpanded(typeId, brandId = "") {
  if (typeId) {
    state.expandedInventoryTypeIds = [...new Set(state.expandedInventoryTypeIds.concat(typeId))];
  }
  if (brandId) {
    state.expandedInventoryBrandIds = [...new Set(state.expandedInventoryBrandIds.concat(brandId))];
  }
}

function expandVisibleInventoryNodes() {
  const nodes = buildInventoryTreeNodes();
  state.expandedInventoryTypeIds = [
    ...new Set(state.expandedInventoryTypeIds.concat(nodes.map(({ type }) => type.id))),
  ];
  state.expandedInventoryBrandIds = [
    ...new Set(state.expandedInventoryBrandIds.concat(nodes.flatMap(({ brands }) => brands.map((brand) => brand.id)))),
  ];
  persistState(false);
}

function getOrgSelectOptions(options = {}) {
  const {
    includeBlank = false,
    blankLabel = "未分配组织",
    excludeIds = [],
  } = options;
  const excluded = new Set(excludeIds);
  const rows = [];

  function visit(org, depth) {
    if (!excluded.has(org.id)) {
      rows.push({
        value: org.id,
        label: `${"　".repeat(depth)}${org.name} · ${org.code}`,
      });
      getOrgChildren(org.id).forEach((child) => visit(child, depth + 1));
    }
  }

  getRootOrgs().forEach((org) => visit(org, 0));

  if (includeBlank) {
    rows.unshift({ value: "", label: blankLabel });
  }
  return rows;
}

function employeeDevices(employee) {
  const devices = [];

  state.computers
    .filter((computer) => computer.userId === employee.id)
    .forEach((computer) => {
      devices.push({
        id: computer.id,
        label: computer.deviceName,
        detail: [computer.brand, computer.model].filter(Boolean).join(" ") || deviceTypeLabel(computer.deviceType),
        category: "computer",
      });
    });

  (employee.monitors || []).forEach((monitor) => {
    devices.push({
      label: "显示屏",
      detail: [monitor.brand, monitor.model].filter(Boolean).join(" ") || "未填写品牌型号",
      quantity: 1,
      category: "monitor",
      typeId: monitor.typeId || defaultMonitorTypeId(),
      brand: monitor.brand || "",
      model: monitor.model || "",
      brandId: monitor.inventoryBrandId || "",
      modelId: monitor.inventoryModelId || "",
    });
  });

  getNonAssetItems(employee).forEach((item) => {
    const quantity = Math.max(0, Number(item.quantity || 0));
    const type = getType(item.typeId);
    if (type && quantity > 0) {
      devices.push({
        label: type.name,
        detail: `${[item.brand, item.model].filter(Boolean).join(" ") || "未填写品牌型号"} · ${quantity}${type.unit || "件"}`,
        quantity,
        category: "non-asset",
        typeId: item.typeId,
        brand: item.brand || "",
        model: item.model || "",
        brandId: item.inventoryBrandId || "",
        modelId: item.inventoryModelId || "",
      });
    }
  });

  return devices;
}

function employeeDeviceSnapshot(employee) {
  const snapshot = [];

  state.computers
    .filter((computer) => computer.userId === employee.id)
    .forEach((computer) => {
      snapshot.push({
        category: "computer",
        label: computer.deviceName,
        detail: [computer.brand, computer.model].filter(Boolean).join(" ") || deviceTypeLabel(computer.deviceType),
        quantity: 1,
      });
    });

  (employee.monitors || []).forEach((monitor) => {
    snapshot.push({
      category: "monitor",
      typeId: monitor.typeId || defaultMonitorTypeId(),
      typeName: getType(monitor.typeId || defaultMonitorTypeId())?.name || "\u663e\u793a\u5c4f",
      brandId: monitor.inventoryBrandId || "",
      modelId: monitor.inventoryModelId || "",
      brand: monitor.brand || "",
      model: monitor.model || "",
      label: "显示屏",
      detail: [monitor.brand, monitor.model].filter(Boolean).join(" ") || "未填写品牌型号",
      quantity: 1,
    });
  });

  getNonAssetItems(employee).forEach((item) => {
    const quantity = Math.max(0, Number(item.quantity || 0));
    const type = getType(item.typeId);
    if (type && quantity > 0) {
      snapshot.push({
        category: "non-asset",
        label: type.name,
        detail: [item.brand, item.model].filter(Boolean).join(" ") || "未填写品牌型号",
        quantity,
        typeId: item.typeId,
        typeName: type.name,
        brandId: item.inventoryBrandId || "",
        modelId: item.inventoryModelId || "",
        brand: item.brand || "",
        model: item.model || "",
      });
    }
  });

  return snapshot;
}

function buildArchivedEmployeeRecord(employee, archiveInput = {}) {
  const existing = getLeftEmployeeBySource(employee.id, employee.employeeNo);
  return {
    id: existing?.id || createId("left"),
    sourceEmployeeId: employee.id || "",
    employeeNo: employee.employeeNo || "",
    name: employee.name || "",
    orgId: employee.orgId || "",
    orgPath: orgPathName(employee.orgId),
    department: employee.department || "",
    position: employee.position || "",
    email: employee.email || "",
    mobile: employee.mobile || "",
    leaveDate: archiveInput.leaveDate || existing?.leaveDate || currentDateText(),
    leaveInfo: archiveInput.leaveInfo || existing?.leaveInfo || "",
    leaveRemark: archiveInput.leaveRemark || existing?.leaveRemark || "",
    archivedAt: archiveInput.archivedAt || existing?.archivedAt || currentTimestampText(),
    devices: employeeDeviceSnapshot(employee),
  };
}

function archiveEmployee(employee, archiveInput = {}) {
  const archiveRecord = buildArchivedEmployeeRecord(employee, archiveInput);
  state.leftEmployees = [archiveRecord].concat(
    state.leftEmployees.filter(
      (item) => item.id !== archiveRecord.id && item.sourceEmployeeId !== archiveRecord.sourceEmployeeId,
    ),
  );

  state.employees = state.employees.filter((item) => item.id !== employee.id);
  state.selectedEmployeeIds = state.selectedEmployeeIds.filter((id) => id !== employee.id);

  state.computers = state.computers.map((computer) => {
    if (computer.userId !== employee.id) return computer;
    return normalizeComputerRecord({
      ...computer,
      userId: null,
      status: "idle",
    });
  });
  normalizeComputersAgainstEmployees();
  return archiveRecord;
}

function employeeRecoveryDevices(employee) {
  const devices = [];
  state.computers
    .filter((computer) => computer.userId === employee.id)
    .forEach((computer) => {
      devices.push({
        key: `computer:${computer.id}`,
        category: "computer",
        label: computer.deviceName,
        detail: [computer.brand, computer.model].filter(Boolean).join(" ") || computer.deviceType,
        quantity: 1,
      });
    });
  (employee.monitors || []).forEach((monitor) => {
    devices.push({
      key: `monitor:${monitor.id}`,
      category: "monitor",
      label: "\u663e\u793a\u5c4f",
      detail: [monitor.brand, monitor.model].filter(Boolean).join(" ") || "\u672a\u586b\u5199\u54c1\u724c\u578b\u53f7",
      quantity: 1,
      typeId: monitor.typeId || defaultMonitorTypeId(),
      typeName: getType(monitor.typeId || defaultMonitorTypeId())?.name || "\u663e\u793a\u5c4f",
      brand: monitor.brand || "",
      model: monitor.model || "",
      brandId: monitor.inventoryBrandId || "",
      modelId: monitor.inventoryModelId || "",
    });
  });
  getNonAssetItems(employee).forEach((item) => {
    const type = getType(item.typeId);
    if (!type || Number(item.quantity || 0) <= 0) return;
    devices.push({
      key: `nonasset:${item.id}`,
      category: "non-asset",
      label: type.name,
      detail: [item.brand, item.model].filter(Boolean).join(" ") || "\u672a\u586b\u5199\u54c1\u724c\u578b\u53f7",
      quantity: Math.max(1, Number(item.quantity || 1)),
      typeId: item.typeId,
      typeName: type.name,
      brand: item.brand || "",
      model: item.model || "",
      brandId: item.inventoryBrandId || "",
      modelId: item.inventoryModelId || "",
    });
  });
  return devices;
}

function ensureInventoryPathForReturn(device) {
  const selectedModel = device.modelId ? getInventoryModel(device.modelId) : null;
  if (selectedModel) return selectedModel;

  let type = getType(device.typeId);
  if (!type) {
    const typeName = device.typeName || device.label || "Other";
    let sequence = 1;
    let code = `inventory_${Date.now().toString(36)}`;
    while (state.nonAssetTypes.some((item) => item.code === code)) {
      sequence += 1;
      code = `inventory_${Date.now().toString(36)}_${sequence}`;
    }
    type = { id: createId("type"), code, name: typeName, unit: "件" };
    state.nonAssetTypes.push(type);
  }

  const brandName = String(device.brand || "未指定").trim() || "未指定";
  let brand =
    (device.brandId && getInventoryBrand(device.brandId)) ||
    state.inventoryBrands.find((item) => item.typeId === type.id && item.name === brandName);
  if (!brand) {
    brand = { id: createId("brand"), typeId: type.id, name: brandName, sortOrder: 1000 };
    state.inventoryBrands.push(brand);
  }

  const modelName = String(device.model || "未指定").trim() || "未指定";
  let model =
    (device.modelId && getInventoryModel(device.modelId)) ||
    state.inventoryModels.find((item) => item.typeId === type.id && item.brandId === brand.id && item.name === modelName);
  if (!model) {
    model = {
      id: createId("model"),
      typeId: type.id,
      brandId: brand.id,
      name: modelName,
      batchKey: "",
      quantity: 0,
      sortOrder: 1000,
    };
    state.inventoryModels.push(model);
  }
  return model;
}

function returnDeviceToInventory(device, context = {}) {
  if (!["monitor", "non-asset"].includes(device.category)) return;
  const model = ensureInventoryPathForReturn(device);
  const quantity = Math.max(1, Number(device.quantity || 1));
  model.quantity = Math.max(0, Number(model.quantity || 0)) + quantity;
  const names = modelLogNames(model);
  recordInventoryMovement({
    direction: "increase",
    ...names,
    quantity,
    sourceLabel: context.sourceLabel || employeeLogLabel(context.relatedEmployeeNo, context.relatedEmployeeName) || "外部回收",
    targetLabel: context.targetLabel || "IT物资库存",
    note: context.note || "",
    relatedEmployeeNo: context.relatedEmployeeNo || "",
    relatedEmployeeName: context.relatedEmployeeName || "",
    triggerAction: context.triggerAction || "return",
  });
}

function recoveryDeviceFromSelection(employee, kind, id) {
  if (!employee || !id) return null;
  if (kind === "monitor") {
    const monitor = (employee.monitors || []).find((item) => item.id === id);
    if (!monitor) return null;
    const typeId = monitor.typeId || defaultMonitorTypeId();
    return {
      key: `monitor:${monitor.id}`,
      category: "monitor",
      label: getType(typeId)?.name || "显示屏",
      detail: [monitor.brand, monitor.model].filter(Boolean).join(" ") || "未填写品牌型号",
      quantity: 1,
      typeId,
      typeName: getType(typeId)?.name || "显示屏",
      brand: monitor.brand || "",
      model: monitor.model || "",
      brandId: monitor.inventoryBrandId || "",
      modelId: monitor.inventoryModelId || "",
      sourceId: monitor.id,
    };
  }
  if (kind === "nonasset") {
    const item = getNonAssetItems(employee).find((entry) => entry.id === id);
    if (!item) return null;
    return {
      key: `nonasset:${item.id}`,
      category: "non-asset",
      label: getType(item.typeId)?.name || "非资产设备",
      detail: [item.brand, item.model].filter(Boolean).join(" ") || "未填写品牌型号",
      quantity: Math.max(1, Number(item.quantity || 1)),
      typeId: item.typeId,
      typeName: getType(item.typeId)?.name || "非资产设备",
      brand: item.brand || "",
      model: item.model || "",
      brandId: item.inventoryBrandId || "",
      modelId: item.inventoryModelId || "",
      sourceId: item.id,
    };
  }
  return null;
}

function openDeviceRecoveryConfirm(employeeId, kind) {
  const employee = getEmployee(employeeId);
  if (!employee) return;
  const selectedIds = [...document.querySelectorAll("[data-recovery-select]:checked")]
    .filter(
      (input) =>
        input.dataset.employeeId === employeeId &&
        input.dataset.recoveryKind === kind &&
        input.dataset.id,
    )
    .map((input) => input.dataset.id);
  const devices = selectedIds
    .map((id) => recoveryDeviceFromSelection(employee, kind, id))
    .filter(Boolean);
  if (!devices.length) {
    showToast(kind === "monitor" ? "请先勾选要回收的显示屏" : "请先勾选要回收的非资产设备", true);
    return;
  }
  pendingDeviceRecovery = { employeeId, kind, devices };
  openModal(
    `${modalHeader("确认回收物资", `${employee.name} · ${employee.employeeNo}`)}
      <div class="confirm-panel">
        <p>是否回收以下物资到 IT 物资库存？</p>
        <div class="recovery-list">
          ${devices
            .map(
              (device) => `
                <div class="recovery-row">
                  <span><strong>${escapeHtml(device.label)}</strong><small>${escapeHtml(
                    `${device.detail}${device.quantity > 1 ? ` x${device.quantity}` : ""}`,
                  )}</small></span>
                </div>`,
            )
            .join("")}
        </div>
        <div class="confirm-options">
          <button class="primary-button" data-action="confirm-device-recovery">确定回收</button>
          <button class="secondary-button" data-action="cancel-device-recovery">取消</button>
        </div>
      </div>`,
    false,
  );
}

function confirmDeviceRecovery() {
  const pending = pendingDeviceRecovery;
  pendingDeviceRecovery = null;
  if (!pending) return;
  const employee = getEmployee(pending.employeeId);
  if (!employee) {
    closeModal();
    render();
    return;
  }
  pending.devices.forEach((device) =>
    returnDeviceToInventory(device, {
      sourceLabel: employeeLogLabel(employee.employeeNo, employee.name),
      targetLabel: "IT物资库存",
      note: device.category === "monitor" ? "人员显示屏回收入库" : "人员非资产设备回收入库",
      relatedEmployeeNo: employee.employeeNo || "",
      relatedEmployeeName: employee.name || "",
      triggerAction: "employee_device_recovery",
    }),
  );
  if (pending.kind === "monitor") {
    const removedIds = new Set(pending.devices.map((device) => device.sourceId));
    employee.monitors = (employee.monitors || []).filter((monitor) => !removedIds.has(monitor.id));
  } else {
    const removedIds = new Set(pending.devices.map((device) => device.sourceId));
    employee.nonAssetItems = getNonAssetItems(employee).filter((item) => !removedIds.has(item.id));
    syncNonAssetAggregate(employee);
  }
  persistState(true);
  closeModal();
  openDeviceManager(employee.id);
  render();
  showToast(`已回收 ${pending.devices.length} 条物资并入库`);
}

function openLeaveRecoveryModal(employee, archiveInput) {
  const devices = employeeRecoveryDevices(employee);
  pendingLeaveRecovery = { employee, archiveInput, devices };
  openModal(
    `${modalHeader("离职物资回收", `${employee.name || employee.employeeNo} 即将离职`)}
      <div class="recovery-list">
        ${
          devices.length
            ? devices
                .map((device) => {
                  const recoverable = device.category !== "computer";
                  return `
                    <label class="recovery-row">
                      <input type="checkbox" data-recovery-key="${escapeHtml(device.key)}" ${
                        recoverable ? "checked" : "checked disabled"
                      } />
                      <span><strong>${escapeHtml(device.label)}</strong><small>${escapeHtml(
                        `${device.detail}${device.quantity > 1 ? ` x${device.quantity}` : ""}`,
                      )}${recoverable ? "" : " / 仅解除电脑分配"}</small></span>
                    </label>
                  `;
                })
                .join("")
            : '<div class="empty-state">当前无已分配设备</div>'
        }
      </div>
      <div class="modal-footer"><button type="button" class="secondary-button" data-action="cancel-leave-recovery">取消</button><button class="primary-button" data-action="confirm-leave-recovery">确认离职并回收</button></div>`,
    true,
  );
}

function confirmLeaveRecovery() {
  const pending = pendingLeaveRecovery;
  pendingLeaveRecovery = null;
  if (!pending) return;
  const selected = new Set(
    [...document.querySelectorAll("[data-recovery-key]")]
      .filter((input) => input.checked)
      .map((input) => input.dataset.recoveryKey),
  );
  const archived = archiveEmployee(pending.employee, pending.archiveInput);
  pending.devices
    .filter((device) => device.category !== "computer" && selected.has(device.key))
    .forEach((device) =>
      returnDeviceToInventory(device, {
        sourceLabel: employeeLogLabel(pending.employee.employeeNo, pending.employee.name),
        targetLabel: "IT物资库存",
        note: "离职回收入库",
        relatedEmployeeNo: pending.employee.employeeNo || "",
        relatedEmployeeName: pending.employee.name || "",
        triggerAction: "leave_recovery",
      }),
    );
  persistState(true);
  closeModal();
  render();
  showToast(`人员已归档，回收 ${Math.max(0, selected.size - pending.devices.filter((item) => item.category === "computer").length)} 条物资。`);
  return archived;
}

function leftEmployeeDeviceChips(devices) {
  if (!devices.length) return '<span class="secondary-text">暂无离职设备快照</span>';
  return `<div class="device-list">${devices
    .map(
      (device) =>
        `<span class="device-chip">${escapeHtml(device.label)}<small>${escapeHtml(
          [device.detail, device.quantity > 1 ? `x${device.quantity}` : ""].filter(Boolean).join(" · "),
        )}</small></span>`,
    )
    .join("")}</div>`;
}

function deviceChips(employee) {
  const devices = employeeDevices(employee);
  if (!devices.length) return '<span class="secondary-text">暂无设备</span>';
  return `<div class="device-list">${devices
    .map(
      (device) =>
        device.category === "computer"
          ? `<button class="device-chip device-chip-button" data-action="open-computer" data-id="${escapeHtml(
              device.id,
            )}" title="查看电脑信息">${escapeHtml(device.label)}<small>${escapeHtml(device.detail)}</small></button>`
          : `<span class="device-chip">${escapeHtml(device.label)}<small>${escapeHtml(device.detail)}</small></span>`,
    )
    .join("")}</div>`;
}

function render() {
  if (!authState.authenticated) {
    renderAuthScreen();
    return;
  }
  const meta = pageMeta[state.page] || pageMeta.dashboard;
  const appName = settingsState.settings.app_name || "办公资产管理系统";
  document.title = `${meta.title} · ${appName}`;
  document.querySelector("#pageTitle").textContent = meta.title;
  document.querySelectorAll(".nav-item").forEach((item) => {
    item.classList.toggle("is-active", item.dataset.page === state.page);
  });
  updateAuthenticatedChrome();
  document.querySelector("#appContent").innerHTML = renderPage();
}

function renderPreservingFilterInput(filterName) {
  const active = document.activeElement;
  const shouldRestore = active?.matches?.(`[data-filter="${CSS.escape(filterName)}"]`);
  const start = shouldRestore && typeof active.selectionStart === "number" ? active.selectionStart : null;
  const end = shouldRestore && typeof active.selectionEnd === "number" ? active.selectionEnd : null;
  render();
  if (!shouldRestore) return;
  const next = document.querySelector(`[data-filter="${CSS.escape(filterName)}"]`);
  if (!next) return;
  next.focus();
  if (start !== null && typeof next.setSelectionRange === "function") {
    next.setSelectionRange(start, end ?? start);
  }
}

function employeeSearchDraftValue(filterName) {
  if (!Object.prototype.hasOwnProperty.call(employeeSearchDrafts, filterName)) {
    employeeSearchDrafts[filterName] = state.filters[filterName] || "";
  }
  return employeeSearchDrafts[filterName] || "";
}

function syncEmployeeSearchDraftsFromFilters() {
  employeeSearchDrafts = {
    employees: state.filters.employees || "",
    employeeAssetSearch: state.filters.employeeAssetSearch || "",
  };
}

function applyEmployeeSearchFilters() {
  state.filters.employees = employeeSearchDraftValue("employees");
  state.filters.employeeAssetSearch = employeeSearchDraftValue("employeeAssetSearch");
  persistState(false);
  render();
}

function renderPage() {
  if (state.page === "computers") return renderComputersPage();
  if (state.page === "employees") return renderEmployeesPage();
  if (state.page === "leftEmployees") return renderLeftEmployeesPage();
  if (state.page === "inventory") return renderInventoryPage();
  if (state.page === "dictionary") return renderDictionaryPage();
  if (state.page === "audit") return renderAuditPage();
  if (state.page === "settings") return renderSettingsPage();
  return renderDashboardPage();
}

function renderSettingsUserTable() {
  const users = Array.isArray(settingsState.users) ? settingsState.users : [];
  if (!users.length) {
    return '<div class="empty-state">暂无账号记录</div>';
  }
  return `<div class="table-wrap"><table class="settings-users-table">
    <thead><tr><th>账号</th><th>显示名称</th><th>角色</th><th>状态</th><th>最后登录</th><th>创建时间</th><th>操作</th></tr></thead>
    <tbody>${users
      .map((user) => {
        const isCurrent = String(user.id) === String(authState.user?.id);
        return `<tr>
          <td><strong>${escapeHtml(user.username)}</strong>${isCurrent ? '<span class="current-account-mark">当前账号</span>' : ""}</td>
          <td>${escapeHtml(user.displayName || "—")}</td>
          <td><span class="role-pill role-${escapeHtml(user.role)}">${escapeHtml(authRoleLabel(user.role))}</span></td>
          <td>${user.isActive ? '<span class="status-pill status-active">启用</span>' : '<span class="status-pill status-inactive">停用</span>'}</td>
          <td>${escapeHtml(formatDateTime(user.lastLoginAt || ""))}</td>
          <td>${escapeHtml(formatDateTime(user.createdAt || ""))}</td>
          <td><button class="text-button" data-action="open-settings-user" data-id="${escapeHtml(user.id)}">编辑</button></td>
        </tr>`;
      })
      .join("")}</tbody>
  </table></div>`;
}

function formatFileSize(value) {
  const bytes = Math.max(0, Number(value || 0));
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let size = bytes / 1024;
  let index = 0;
  while (size >= 1024 && index < units.length - 1) {
    size /= 1024;
    index += 1;
  }
  return `${size >= 10 ? size.toFixed(1) : size.toFixed(2)} ${units[index]}`;
}

function databaseBackupTypeLabel(type) {
  return type === "scheduled" ? "定时备份" : "手动备份";
}

function databaseBackupStatusLabel(backup) {
  if (backup.status === "expired") return "已清理";
  if (backup.status === "failed") return "失败";
  return backup.fileAvailable ? "可下载" : "文件缺失";
}

function renderDatabaseBackupTable() {
  const backups = Array.isArray(settingsState.backups) ? settingsState.backups : [];
  if (!backups.length) {
    return '<div class="empty-state">尚无数据库备份记录</div>';
  }
  return `<div class="table-wrap"><table class="settings-backups-table">
    <thead><tr><th>创建时间</th><th>类型</th><th>备份文件</th><th>大小</th><th>创建人</th><th>状态</th><th>操作</th></tr></thead>
    <tbody>${backups
      .map(
        (backup) => `<tr>
          <td>${escapeHtml(formatDateTime(backup.createdAt || ""))}</td>
          <td>${escapeHtml(databaseBackupTypeLabel(backup.backupType))}</td>
          <td><strong>${escapeHtml(backup.fileName || "—")}</strong></td>
          <td>${escapeHtml(formatFileSize(backup.fileSize))}</td>
          <td>${escapeHtml(backup.requestedByName || "系统")}</td>
          <td><span class="backup-status backup-status-${escapeHtml(backup.status || "completed")}">${
            escapeHtml(databaseBackupStatusLabel(backup))
          }</span></td>
          <td><button class="text-button" data-action="open-database-backup-download" data-id="${escapeHtml(
            backup.id,
          )}" ${backup.fileAvailable ? "" : "disabled"}>下载</button></td>
        </tr>`,
      )
      .join("")}</tbody>
  </table></div>`;
}

function updateStatusLabel(status) {
  if (status === "queued") return "发现新版本，更新已排队";
  if (status === "running") return "更新正在执行";
  if (status === "up_to_date") return "当前已是最新版本";
  return "尚未检查";
}

function updateStatusDetail(status) {
  if (status === "queued") return "服务器将从 Gitea 拉取最新 main 分支并重新构建应用。";
  if (status === "running") return "应用服务可能会短暂重启，请稍后刷新页面。";
  if (status === "up_to_date") return "当前部署版本与服务器 Gitea 仓库一致。";
  return "点击按钮检查服务器 Gitea 是否有新的应用版本。";
}

function renderUpdatePanel(admin) {
  if (!admin) {
    return `<section class="data-panel settings-panel settings-readonly-note">
      <strong>版本更新</strong><span>只有管理员可以检查并执行 Gitea 版本更新。</span>
    </section>`;
  }
  const status = settingsState.updateStatus || {};
  const checking = settingsState.updateChecking;
  const currentSha = status.currentShortSha || (status.currentSha ? String(status.currentSha).slice(0, 7) : "-");
  const latestSha = status.latestShortSha || (status.latestSha ? String(status.latestSha).slice(0, 7) : "-");
  const statusValue = status.status || "";
  return `<section class="data-panel settings-panel update-panel">
    <div class="section-heading settings-panel-heading">
      <div><h2>版本更新</h2><span>从服务器 Gitea 检查 main 分支，有新版本时直接更新应用。</span></div>
    </div>
    <div class="update-version-grid">
      <div class="update-version-item"><span>当前版本</span><strong>${escapeHtml(currentSha)}</strong></div>
      <div class="update-version-item"><span>Gitea 最新版本</span><strong>${escapeHtml(latestSha)}</strong></div>
    </div>
    <div class="settings-readonly-note update-status-note">
      <strong>${escapeHtml(updateStatusLabel(statusValue))}</strong>
      <span>${escapeHtml(updateStatusDetail(statusValue))}</span>
    </div>
    <div class="modal-footer settings-form-footer">
      <button type="button" class="primary-button" data-action="check-for-update" ${checking ? "disabled" : ""}>
        ${checking ? "正在检查..." : "检查更新"}
      </button>
    </div>
  </section>`;
}

function renderSettingsPage() {
  if (!settingsState.loaded) {
    return `<div class="page-intro"><div><h2>系统设置</h2><p>正在加载设置数据。</p></div></div>
      <section class="data-panel settings-loading">正在读取系统设置...</section>`;
  }
  const settings = settingsState.settings || {};
  const admin = isAdminUser();
  return `
    <div class="page-intro">
      <div><h2>系统设置</h2><p>维护系统显示参数、登录安全和账号信息。</p></div>
    </div>
    <div class="settings-grid">
      <section class="data-panel settings-panel">
        <div class="section-heading settings-panel-heading">
          <div><h2>系统参数</h2><span>${admin ? "管理员可以修改系统级设置。" : "当前账号只能查看系统级设置。"}</span></div>
        </div>
        <form data-form="system-settings" class="settings-form">
          <div class="form-grid">
            ${inputField("系统名称", "app_name", settings.app_name || "办公资产管理系统", true, "办公资产管理系统", "text", "", admin ? "" : "readonly")}
            ${inputField("会话时长（小时）", "session_hours", settings.session_hours || "8", true, "8", "number", "1", admin ? 'max="168"' : 'readonly max="168"')}
          </div>
          ${textareaField("登录页提示语", "login_notice", settings.login_notice || "", false, "例如：请使用公司账号登录", 4, admin ? "" : "readonly")}
          <div class="modal-footer settings-form-footer">${admin ? '<button class="primary-button" type="submit">保存系统设置</button>' : '<span class="secondary-text">只有管理员可以保存系统设置</span>'}</div>
        </form>
      </section>

      <section class="data-panel settings-panel">
        <div class="section-heading settings-panel-heading">
          <div><h2>修改我的密码</h2><span>密码至少 8 位，修改后当前会话仍保持有效。</span></div>
        </div>
        <form data-form="change-password" class="settings-form">
          ${inputField("当前密码", "currentPassword", "", true, "请输入当前密码", "password", "8", 'autocomplete="current-password"')}
          <div class="form-grid">
            ${inputField("新密码", "newPassword", "", true, "至少 8 位", "password", "8", 'autocomplete="new-password"')}
            ${inputField("确认新密码", "confirmPassword", "", true, "再次输入新密码", "password", "8", 'autocomplete="new-password"')}
          </div>
          <div class="modal-footer settings-form-footer"><button class="primary-button" type="submit">保存新密码</button></div>
        </form>
      </section>
      ${renderUpdatePanel(admin)}
    </div>

    ${
      admin
        ? `<section class="section-block">
            <div class="section-heading">
              <div><h2>数据库备份</h2><span>备份文件仅保存在服务器的非公开目录；下载前需要重新验证当前登录账号密码。</span></div>
              <div class="toolbar-actions">
                <button type="button" class="primary-button" data-action="create-database-backup">立即备份</button>
              </div>
            </div>
            <div class="settings-grid">
              <section class="data-panel settings-panel">
                <div class="section-heading settings-panel-heading">
                  <div><h2>自动备份计划</h2><span>服务运行期间每天在指定时间执行一次备份。</span></div>
                </div>
                <form data-form="backup-schedule" class="settings-form">
                  <div class="form-grid">
                    <div class="form-field backup-toggle-field">
                      <label class="backup-toggle-label"><input type="checkbox" name="backup_enabled" ${
                        ["1", "true", "yes", "on"].includes(String(settings.backup_enabled || "").toLowerCase())
                          ? "checked"
                          : ""
                      } /><span>启用每日自动备份</span></label>
                      <p class="form-hint">服务重启后会继续按当前设置执行。</p>
                    </div>
                    ${inputField("每日备份时间", "backup_time", settings.backup_time || "02:00", true, "", "time")}
                    ${inputField(
                      "保留天数",
                      "backup_retention_days",
                      settings.backup_retention_days || "30",
                      true,
                      "0 表示不自动清理",
                      "number",
                      "0",
                      'max="3650"',
                    )}
                  </div>
                  <div class="modal-footer settings-form-footer"><button class="primary-button" type="submit">保存备份计划</button></div>
                </form>
              </section>
              <section class="data-panel settings-panel">
                <div class="section-heading settings-panel-heading">
                  <div><h2>备份说明</h2><span>手动备份会立即创建一个压缩的 SQL 文件。</span></div>
                </div>
                <div class="settings-readonly-note"><strong>下载保护</strong><span>下载任意备份时，系统会要求再次输入当前管理员账号的登录密码。备份文件不会暴露在网页静态目录中。</span></div>
              </section>
            </div>
            <section class="data-panel settings-backup-list">${renderDatabaseBackupTable()}</section>
          </section>`
        : `<section class="section-block"><section class="data-panel settings-readonly-note"><strong>数据库备份</strong><span>只有管理员可以创建、配置、查看和下载数据库备份。</span></section></section>`
    }

    ${
      admin
        ? `<section class="section-block">
            <div class="section-heading">
              <div><h2>账号管理</h2><span>管理员、操作员和只读用户拥有不同的数据操作范围。</span></div>
              <div class="toolbar-actions"><button class="primary-button" data-action="open-settings-user">＋ 新增账号</button></div>
            </div>
            <section class="data-panel">${renderSettingsUserTable()}</section>
          </section>`
        : `<section class="section-block"><section class="data-panel settings-readonly-note"><strong>账号管理</strong><span>只有管理员可以新增、修改或停用账号。</span></section></section>`
    }`;
}

function openSettingsUserModal(id = "") {
  if (!isAdminUser()) {
    showToast("只有管理员可以管理账号", true);
    return;
  }
  const user = settingsState.users.find((item) => String(item.id) === String(id)) || {
    id: "",
    username: "",
    displayName: "",
    role: "operator",
    isActive: true,
  };
  const isEditing = Boolean(user.id);
  openModal(
    `${modalHeader(isEditing ? "编辑账号" : "新增账号", "账号用于登录系统，密码不会显示在页面或日志中。")}
      <form data-form="user-account" data-id="${escapeHtml(user.id)}">
        <div class="form-grid">
          ${inputField("登录账号", "username", user.username, !isEditing, "3-64 位字母、数字、点、下划线或短横线", "text", "", isEditing ? "readonly" : 'autocomplete="username"')}
          ${inputField("显示名称", "displayName", user.displayName, true, "例如：张三")}
          ${selectField("角色", "role", user.role, Object.entries(roleLabels).map(([value, label]) => ({ value, label })), true)}
          ${selectField("账号状态", "isActive", user.isActive ? "1" : "0", [
            { value: "1", label: "启用" },
            { value: "0", label: "停用" },
          ], true)}
        </div>
        ${inputField(isEditing ? "重置密码（可选）" : "初始密码", "password", "", !isEditing, isEditing ? "留空表示不修改" : "至少 8 位", "password", "8", 'autocomplete="new-password"')}
        <div class="modal-footer"><button type="button" class="secondary-button" data-action="close-modal">取消</button><button class="primary-button" type="submit">${isEditing ? "保存账号" : "创建账号"}</button></div>
      </form>`,
    false,
  );
}

function openDatabaseBackupDownloadModal(id = "") {
  if (!isAdminUser()) {
    showToast("只有管理员可以下载数据库备份", true);
    return;
  }
  const backup = (settingsState.backups || []).find((item) => String(item.id) === String(id));
  if (!backup || !backup.fileAvailable) {
    showToast("该备份文件当前不可下载", true);
    return;
  }
  openModal(
    `${modalHeader("下载数据库备份", "请重新输入当前登录账号的密码以确认本次下载。")}
      <form data-form="database-backup-download" data-id="${escapeHtml(backup.id)}">
        <div class="backup-download-file"><strong>${escapeHtml(backup.fileName)}</strong><span>${escapeHtml(
          `${formatFileSize(backup.fileSize)} · ${formatDateTime(backup.createdAt || "")}`,
        )}</span></div>
        ${inputField("当前账号密码", "password", "", true, "请输入当前登录账号密码", "password", "8", 'autocomplete="current-password"')}
        <div class="modal-footer"><button type="button" class="secondary-button" data-action="close-modal">取消</button><button class="primary-button" type="submit">确认下载</button></div>
      </form>`,
    false,
  );
}

const auditActionLabels = {
  employee_added: "新增人员",
  employee_removed: "删除人员",
  employee_archived: "离职归档",
  employee_status_changed: "人员状态变更",
  computer_status_changed: "电脑状态变更",
  computer_assignment_changed: "电脑分配变更",
  computer_added: "新增办公电脑",
  computer_removed: "删除办公电脑",
  monitor_added: "增加显示屏",
  monitor_removed: "减少显示屏",
  non_asset_added: "增加非资产设备",
  non_asset_removed: "减少非资产设备",
  non_asset_quantity_changed: "非资产数量变更",
  inventory_group_added: "库存组新增",
  inventory_group_changed: "库存组变更",
  inventory_group_removed: "库存组删除",
  inventory_stock_changed: "库存数量变更",
};

function auditActionLabel(actionType) {
  return auditActionLabels[actionType] || auditActionExtraLabels[actionType] || actionType || "其他操作";
}

const auditActionExtraLabels = {
  employee_info_changed: "人员信息变更",
  computer_info_changed: "电脑信息变更",
  monitor_changed: "人员显示屏信息变更",
  non_asset_changed: "人员非资产物资信息变更",
  inventory_type_changed: "物资类型变更",
  inventory_brand_changed: "物资品牌变更",
  inventory_model_changed: "物资型号变更",
  database_backup_created: "手动创建数据库备份",
  database_backup_scheduled: "定时创建数据库备份",
  database_backup_schedule_changed: "数据库自动备份设置变更",
  database_backup_downloaded: "下载数据库备份",
};

const auditCategoryLabels = {
  inventory: "物资变动",
  employee: "人员变动",
  computer: "电脑信息变动",
  organization: "组织架构变动",
  other: "其他变动",
};

function auditCategoryForLog(log) {
  if (log?.category) return log.category;
  if (["inventory_type", "inventory_brand", "inventory_model"].includes(log?.entityType)) {
    return "inventory";
  }
  if (["employee", "monitor", "non_asset"].includes(log?.entityType)) {
    return "employee";
  }
  if (log?.entityType === "computer") return "computer";
  if (log?.entityType === "org_unit") return "organization";
  return "other";
}

function auditCategoryLabel(category) {
  return auditCategoryLabels[category] || category || "其他变动";
}

function auditChangeLabel(log) {
  const oldQuantity = Number(log?.oldValue?.quantity || 0);
  const newQuantity = Number(log?.newValue?.quantity || 0);
  if (log?.actionType === "inventory_stock_changed") {
    if (newQuantity > oldQuantity) return "物资库存增加";
    if (newQuantity < oldQuantity) return "物资库存减少";
  }
  if (log?.actionType === "non_asset_quantity_changed") {
    if (newQuantity > oldQuantity) return "人员物资增加";
    if (newQuantity < oldQuantity) return "人员物资减少";
  }
  return log?.changeLabel || auditActionLabel(log?.actionType);
}

function auditCategoryClass(log) {
  return `audit-category-${auditCategoryForLog(log)}`;
}

function getAuditCategoryOptions() {
  return ["inventory", "employee", "computer", "organization"];
}

const auditEntityTypeLabels = {
  it_inventory: "IT物资",
  inventory_type: "IT物资类型",
  inventory_brand: "IT物资品牌",
  inventory_model: "IT物资型号",
  employee: "使用人员",
  computer: "办公电脑",
  monitor: "显示屏",
  non_asset: "非资产物资",
  org_unit: "组织架构",
};

function auditEntityTypeLabel(entityType) {
  return auditEntityTypeLabels[entityType] || entityType || "其他对象";
}

function getAuditEntityTypeOptions() {
  return ["it_inventory", "employee", "computer", "monitor", "non_asset", "org_unit"];
}

function auditValueText(value) {
  if (value === null || value === undefined || value === "") return "无";
  if (typeof value !== "object") return String(value);

  const fieldLabels = {
    status: "状态",
    department: "部门",
    employeeNo: "人员编号",
    employeeName: "使用人",
    quantity: "数量",
    typeName: "类型",
    typeId: "类型编号",
    brand: "品牌",
    brandId: "品牌编号",
    model: "型号",
    modelId: "型号编号",
    name: "名称",
    deviceName: "设备名",
    orgId: "组织",
    deviceType: "设备类型",
    fixedAssetCode: "固资编码",
    purchaseDate: "购置日期",
    registeredDate: "注册日期",
    snSt: "SN/ST",
    wifiMac: "Wifi MAC",
    ethernetMac: "网口 MAC",
    location: "位置",
    remarks: "备注",
    email: "邮箱",
    mobile: "手机",
    position: "岗位",
  };
  const parts = [];
  Object.entries(value).forEach(([key, item]) => {
    if (key === "assignment" && item && typeof item === "object") {
      parts.push(`使用人：${item.employeeName || "未分配"}`);
      if (item.employeeNo) parts.push(`编号：${item.employeeNo}`);
      return;
    }
    const label = fieldLabels[key] || key;
    const displayValue = key === "status" ? statusLabels[item] || item : item;
    if (displayValue !== null && displayValue !== undefined && displayValue !== "") {
      parts.push(`${label}：${displayValue}`);
    }
  });
  return parts.join("；") || "无";
}

function auditActionClass(actionType) {
  if (actionType.includes("removed") || actionType.includes("status_changed")) return "audit-action-alert";
  if (actionType.includes("assignment")) return "audit-action-assignment";
  if (actionType.includes("changed")) return "audit-action-assignment";
  return "audit-action-added";
}

function getAuditActionOptions() {
  return Object.keys({ ...auditActionLabels, ...auditActionExtraLabels }).sort((a, b) =>
    auditActionLabel(a).localeCompare(auditActionLabel(b), "zh-CN"),
  );
}

function renderAuditPage() {
  const logs = state.auditLogs || [];
  const actionFilter = state.filters.auditAction || "";
  const entityTypeFilter = state.filters.auditEntityType || "";
  const actionOptions = getAuditActionOptions();
  const entityTypeOptions = getAuditEntityTypeOptions();

  return `
    <div class="page-intro">
      <div><h2>操作日志</h2><p>按操作类别查看物资、人员和电脑变动，再结合具体变动、人员和日期进行筛选。</p></div>
      <div class="toolbar-actions">
        <button class="secondary-button" data-action="refresh-audit">刷新日志</button>
        <button class="secondary-button" data-action="export-audit" ${logs.length ? "" : "disabled"}>导出当前结果</button>
      </div>
    </div>
    <div class="toolbar">
      <div class="toolbar-actions">
        <label class="select-box audit-date-box"><span>开始</span><input type="date" data-filter="auditStartDate" value="${escapeHtml(
          state.filters.auditStartDate || "",
        )}" /></label>
        <label class="select-box audit-date-box"><span>结束</span><input type="date" data-filter="auditEndDate" value="${escapeHtml(
          state.filters.auditEndDate || "",
        )}" /></label>
        <label class="search-box audit-employee-box"><span>人</span><input data-filter="auditEmployee" value="${escapeHtml(
          state.filters.auditEmployee || "",
        )}" placeholder="人员编号或姓名" /></label>
        <label class="search-box"><span>⌕</span><input data-filter="auditSearch" value="${escapeHtml(
          state.filters.auditSearch || "",
        )}" placeholder="搜索人员、设备或操作内容..." /></label>
        <label class="select-box"><span>操作类别</span><select data-filter="auditCategory">
          <option value="">全部类别</option>
          ${getAuditCategoryOptions()
            .map(
              (category) =>
                `<option value="${escapeHtml(category)}" ${
                  (state.filters.auditCategory || "") === category ? "selected" : ""
                }>${escapeHtml(auditCategoryLabel(category))}</option>`,
            )
            .join("")}
        </select></label>
        <label class="select-box"><span>具体变动</span><select data-filter="auditAction">
          <option value="">全部变动</option>
          ${actionOptions
            .map(
              (action) =>
                `<option value="${escapeHtml(action)}" ${
                  actionFilter === action ? "selected" : ""
                }>${escapeHtml(auditActionLabel(action))}</option>`,
            )
            .join("")}
        </select></label>
        <label class="select-box"><span>对象范围</span><select data-filter="auditEntityType">
          <option value="">全部对象</option>
          ${entityTypeOptions
            .map(
              (entityType) =>
                `<option value="${escapeHtml(entityType)}" ${
                  entityTypeFilter === entityType ? "selected" : ""
                }>${escapeHtml(auditEntityTypeLabel(entityType))}</option>`,
            )
            .join("")}
        </select></label>
        <button class="primary-button audit-apply-button" data-action="apply-audit-filters">应用筛选</button>
      </div>
      <span class="secondary-text">显示 ${logs.length} / ${state.auditLogTotal || logs.length} 条</span>
    </div>
    <div class="data-panel">${renderAuditTable(logs)}</div>
  `;
}

function renderAuditTable(logs) {
  if (!logs.length) return '<div class="empty-state">暂无符合条件的操作日志</div>';
  return `
    <div class="table-wrap">
      <table class="audit-table">
        <thead><tr><th>时间</th><th>操作类别</th><th>具体变动</th><th>变更对象</th><th>关联人员</th><th>变更前</th><th>变更后</th><th>变更说明</th><th>操作人</th></tr></thead>
        <tbody>
          ${logs
            .map(
              (log) => `<tr>
                <td class="audit-time">${escapeHtml(log.createdAt || "未知时间")}</td>
                <td><span class="audit-category ${auditCategoryClass(log)}">${escapeHtml(
                  auditCategoryLabel(auditCategoryForLog(log)),
                )}</span></td>
                <td><span class="audit-action ${auditActionClass(log.actionType)}">${escapeHtml(
                  auditChangeLabel(log),
                )}</span></td>
                <td><div class="primary-text">${escapeHtml(log.entityName || log.deviceName || "—")}</div><div class="secondary-text">${escapeHtml(
                  auditEntityTypeLabel(log.entityType),
                )}</div></td>
                <td>${
                  log.employeeName
                    ? `<div class="primary-text">${escapeHtml(log.employeeName)}</div><div class="secondary-text mono">${escapeHtml(
                        log.employeeId || "",
                      )}</div>`
                    : '<span class="secondary-text">—</span>'
                }</td>
                <td><span class="audit-value">${escapeHtml(auditValueText(log.oldValue))}</span></td>
                <td><span class="audit-value">${escapeHtml(auditValueText(log.newValue))}</span></td>
                <td class="audit-summary">${escapeHtml(log.summary)}</td>
                <td><div class="primary-text">${escapeHtml(log.actor || "web")}</div><div class="secondary-text">${escapeHtml(
                  log.source || "",
                )}</div></td>
              </tr>`,
            )
            .join("")}
        </tbody>
      </table>
    </div>
  `;
}

function dashboardComputerStatusSummary() {
  const definitions = [
    { key: "in_use", label: statusLabels.in_use, color: "#111111" },
    { key: "idle", label: statusLabels.idle, color: "#777777" },
    { key: "repair", label: statusLabels.repair, color: "#e30613" },
  ];
  const total = state.computers.length;
  const segments = definitions.map((item) => ({
    ...item,
    count: state.computers.filter((computer) => computer.status === item.key).length,
  }));
  const covered = segments.reduce((sum, item) => sum + item.count, 0);
  if (total > covered) {
    segments.push({ key: "other", label: "其它状态", color: "#aaaaaa", count: total - covered });
  }
  return { total, segments };
}

function renderDashboardComputerStatusChart() {
  const { total, segments } = dashboardComputerStatusSummary();
  return `
    <div class="dashboard-status-layout">
      <div class="dashboard-status-number">
        <strong>${total}</strong>
        <span>电脑总数</span>
      </div>
      <div class="dashboard-status-summary">
        <ul class="dashboard-status-legend">
          ${segments
            .map(
              (item) => `
                <li>
                  <div class="dashboard-status-line">
                    <span>${escapeHtml(item.label)}</span>
                    <div class="dashboard-status-meter"><span style="width: ${
                      total ? Math.max(0, Math.round((item.count / total) * 100)) : 0
                    }%; background: ${item.color}"></span></div>
                  </div>
                  <strong>${item.count}</strong>
                </li>`,
            )
            .join("")}
        </ul>
        <span class="dashboard-status-note">在用、闲置、维修状态实时汇总</span>
      </div>
    </div>
  `;
}

function getRecentInventoryInboundLogs(limit = 8) {
  return [...state.inventoryMovementLogs]
    .filter((log) => log.direction === "increase")
    .sort((a, b) => String(b.occurredAt || "").localeCompare(String(a.occurredAt || "")))
    .slice(0, limit);
}

function renderDashboardRecentInboundList() {
  const logs = getRecentInventoryInboundLogs();
  if (!logs.length) return '<div class="empty-state">暂无物资入库记录</div>';
  return `
    <div class="dashboard-inbound-list">
      ${logs
        .map(
          (log) => `
            <div class="dashboard-inbound-row">
              <div class="dashboard-inbound-main">
                <strong>${escapeHtml(log.typeName || "未分类物资")}</strong>
                <span>${escapeHtml([log.brandName, log.modelName].filter(Boolean).join(" / ") || "未填写品牌型号")}</span>
                <small>${escapeHtml(formatDateTime(log.occurredAt))} · ${escapeHtml(log.sourceLabel || "未标注来源")}</small>
              </div>
              <strong class="dashboard-inbound-quantity">+${Math.max(1, Number(log.quantity || 1))}</strong>
            </div>`,
        )
        .join("")}
    </div>
  `;
}

function renderDashboardOrgTreeNode(org, depth = 0) {
  const summary = getOrgSummary(org.id);
  const children = getOrgChildren(org.id);
  return `
    <div class="dashboard-org-node" style="--dashboard-org-depth: ${depth}">
      <div class="dashboard-org-row">
        <span class="dashboard-org-marker" aria-hidden="true"></span>
        <div class="dashboard-org-main">
          <div><strong>${escapeHtml(org.name)}</strong><span>${escapeHtml(org.code)}</span></div>
          <small>${summary.employees} 人 · ${summary.computers} 台电脑${summary.children ? ` · ${summary.children} 个下级` : ""}</small>
        </div>
      </div>
      ${children.length ? `<div class="dashboard-org-children">${children.map((child) => renderDashboardOrgTreeNode(child, depth + 1)).join("")}</div>` : ""}
    </div>
  `;
}

function renderDashboardOrgTree() {
  const roots = getRootOrgs();
  if (!roots.length) return '<div class="empty-state">暂无组织架构</div>';
  return `<div class="dashboard-org-tree">${roots.map((org) => renderDashboardOrgTreeNode(org)).join("")}</div>`;
}

function renderDashboardPage() {
  const computerCount = state.computers.length;
  const inUseCount = state.computers.filter((computer) => computer.status === "in_use").length;
  const activeEmployees = state.employees.filter((employee) => employee.status === "active").length;
  const nonAssetCount = state.employees.reduce(
    (sum, employee) =>
      sum + getNonAssetItems(employee).reduce((total, item) => total + Math.max(0, Number(item.quantity || 0)), 0),
    0,
  );
  const recentComputers = [...state.computers]
    .sort((a, b) => (b.registeredDate || "").localeCompare(a.registeredDate || ""))
    .slice(0, 5);
  const attentionComputers = state.computers.filter((computer) => ["repair", "lost", "retired"].includes(computer.status));

  return `
    <div class="page-intro">
      <div>
        <h2>今天的资产脉搏</h2>
        <p>${formatDate(new Date().toISOString().slice(0, 10))} · 数据已同步至 MySQL</p>
      </div>
      <div class="toolbar-actions">
        <button class="secondary-button" data-action="navigate" data-page="employees">查看组织树</button>
        <button class="primary-button" data-action="open-computer">＋ 新增电脑</button>
      </div>
    </div>

    <div class="stats-grid">
      <div class="stat-card">
        <div class="stat-label"><span>电脑资产</span><span class="stat-mark">▣</span></div>
        <div class="stat-value">${computerCount}</div>
        <div class="stat-foot">${inUseCount} 台当前在用</div>
      </div>
      <div class="stat-card">
        <div class="stat-label"><span>使用人员</span><span class="stat-mark">♙</span></div>
        <div class="stat-value">${activeEmployees}</div>
        <div class="stat-foot">${getRootOrgs().length} 个根组织</div>
      </div>
      <div class="stat-card">
        <div class="stat-label"><span>非资产设备</span><span class="stat-mark">⌁</span></div>
        <div class="stat-value">${nonAssetCount}</div>
        <div class="stat-foot">鼠标、键盘、拓展坞等</div>
      </div>
      <div class="stat-card">
        <div class="stat-label"><span>待关注</span><span class="stat-mark">!</span></div>
        <div class="stat-value">${attentionComputers.length}</div>
        <div class="stat-foot">维修、丢失或报废状态</div>
      </div>
    </div>

    <div class="content-grid">
      <section class="section-block">
        <div class="section-heading">
          <div><h2>最近登记的电脑</h2><span>按注册日期倒序</span></div>
          <button class="text-button" data-action="navigate" data-page="computers">查看全部 →</button>
        </div>
        <div class="data-panel">
          ${renderComputerTable(recentComputers, false)}
        </div>
      </section>
      <section class="section-block">
        <div class="section-heading">
          <div><h2>电脑资产状态</h2><span>在用、闲置、维修分布</span></div>
          <button class="text-button" data-action="navigate" data-page="computers">查看台账 →</button>
        </div>
        <div class="data-panel dashboard-status-panel">
          ${renderDashboardComputerStatusChart()}
        </div>
      </section>
    </div>

    <div class="dashboard-insight-grid">
      <section class="section-block">
        <div class="section-heading">
          <div><h2>最近入库物资</h2><span>按物资增加操作时间倒序</span></div>
          <button class="text-button" data-action="navigate" data-page="inventory">查看物资 →</button>
        </div>
        <div class="data-panel">
          ${renderDashboardRecentInboundList()}
        </div>
      </section>
      <section class="section-block">
        <div class="section-heading">
          <div><h2>组织架构树</h2><span>含人员与电脑数量汇总</span></div>
          <button class="text-button" data-action="navigate" data-page="employees">查看人员 →</button>
        </div>
        <div class="data-panel dashboard-org-tree-panel">
          ${renderDashboardOrgTree()}
        </div>
      </section>
    </div>

    <section class="section-block">
      <div class="section-heading">
        <div><h2>人员设备概览</h2><span>电脑名称、显示屏型号和非资产数量</span></div>
        <button class="text-button" data-action="navigate" data-page="employees">查看组织树 →</button>
      </div>
      <div class="data-panel">
        ${renderEmployeeTable(sortEmployees(state.employees).slice(0, 5), false)}
      </div>
    </section>
  `;
}

function renderRootOrgMetrics() {
  const roots = getRootOrgs();
  if (!roots.length) return '<div class="empty-state">暂无组织架构</div>';
  return `<div class="metric-strip">${roots
    .map((org) => {
      const summary = getOrgSummary(org.id);
      return `<div class="metric-line"><span>${escapeHtml(org.name)}</span><strong>${summary.employees} 人</strong><span class="secondary-text">${summary.computers} 台电脑</span></div>`;
    })
    .join("")}</div>`;
}

function renderComputersPage() {
  const statusFilter = state.filters.computerStatus || "";
  const computers = getFilteredComputers();
  const selectedCount = state.selectedComputerIds.length;

  return `
    <div class="page-intro">
      <div><h2>办公电脑台账</h2><p>共 ${state.computers.length} 台 · 支持按设备名、固资编码、SN/ST、组织和使用用户检索</p></div>
      <div class="toolbar-actions">
        <button class="secondary-button" data-action="select-all-computers">全选当前结果</button>
        <button class="secondary-button" data-action="clear-computer-selection">清空选择</button>
        <button class="secondary-button" data-action="export-computers" ${selectedCount ? "" : "disabled"}>导出选中 ${selectedCount}</button>
        <button class="primary-button" data-action="open-computer">＋ 新增电脑</button>
      </div>
    </div>
    <div class="toolbar">
      <div class="toolbar-actions">
        <label class="search-box"><span>⌕</span><input data-filter="computers" value="${escapeHtml(
          state.filters.computers || "",
        )}" placeholder="搜索设备名、型号、固资编码..." /></label>
        <label class="select-box"><select data-filter="computerStatus">
          <option value="">全部状态</option>
          ${["in_use", "idle", "repair", "retired", "lost"]
            .map(
              (status) =>
                `<option value="${status}" ${statusFilter === status ? "selected" : ""}>${escapeHtml(
                  statusLabels[status],
                )}</option>`,
            )
            .join("")}
        </select></label>
      </div>
      <span class="secondary-text">显示 ${computers.length} / ${state.computers.length} 台</span>
    </div>
    <div class="data-panel">${renderComputerTable(computers, true, true)}</div>
  `;
}

function renderComputerTable(computers, withActions, selectable = false) {
  if (!computers.length) return '<div class="empty-state">暂无符合条件的电脑记录</div>';
  const allVisibleComputersSelected =
    selectable && computers.length > 0 && computers.every((computer) => state.selectedComputerIds.includes(computer.id));
  return `
    <div class="table-wrap">
      <table>
        <thead><tr>
          ${
            selectable
              ? `<th class="selector-cell"><input type="checkbox" data-action="toggle-all-computers" title="选择当前结果" ${
                  allVisibleComputersSelected ? "checked" : ""
                } /></th>`
              : ""
          }
          <th>设备名</th><th>所属组织</th><th>设备类型 / 品牌型号</th><th>固资编码</th>
          <th>位置</th><th>使用用户</th><th>状态</th>${withActions ? "<th>操作</th>" : ""}
        </tr></thead>
        <tbody>
          ${computers
            .map((computer) => {
              const user = getCurrentUser(computer);
              const configSummary = computerConfigSummary(computer);
              return `<tr>
                ${
                  selectable
                    ? `<td class="selector-cell"><input type="checkbox" class="row-selector" data-action="toggle-computer-selection" data-id="${escapeHtml(
                        computer.id,
                      )}" ${state.selectedComputerIds.includes(computer.id) ? "checked" : ""} /></td>`
                    : ""
                }
                <td><div class="primary-text">${escapeHtml(computer.deviceName)}</div><div class="secondary-text">${escapeHtml(
                  computer.snSt || "未登记 SN/ST",
                )}</div>${
                  configSummary
                    ? `<div class="secondary-text">${escapeHtml(configSummary)}</div>`
                    : ""
                }</td>
                <td><div class="primary-text">${escapeHtml(orgName(computer.orgId))}</div><div class="secondary-text">${escapeHtml(
                  orgPathName(computer.orgId),
                )}</div></td>
                <td><div class="primary-text">${escapeHtml(deviceTypeLabel(computer.deviceType))}</div><div class="secondary-text">${escapeHtml(
                  [computer.brand, computer.model].filter(Boolean).join(" · ") || "未填写品牌型号",
                )}</div></td>
                <td class="mono">${escapeHtml(computer.fixedAssetCode || "—")}</td>
                <td>${escapeHtml(computer.location || "—")}</td>
                <td>${
                  user
                    ? `<div class="primary-text">${escapeHtml(user.name)}</div><div class="secondary-text">${escapeHtml(
                        `${orgName(user.orgId)} · ${user.department || "—"}`,
                      )}</div>`
                    : '<span class="secondary-text">未分配</span>'
                }</td>
                <td>${statusPill(computer.status)}</td>
                ${
                  withActions
                    ? `<td><div class="inline-actions">
                        <button class="text-button" data-action="open-computer" data-id="${escapeHtml(computer.id)}">编辑</button>
                        <button class="text-button danger" data-action="delete-computer" data-id="${escapeHtml(computer.id)}">删除</button>
                      </div></td>`
                    : ""
                }
              </tr>`;
            })
            .join("")}
        </tbody>
      </table>
    </div>
  `;
}

function renderEmployeesPage() {
  const search = (state.filters.employees || "").trim().toLowerCase();
  const assetSearch = (state.filters.employeeAssetSearch || "").trim().toLowerCase();
  const statusFilter = state.filters.employeeStatus || "";
  const orgFilter = state.filters.employeeOrg || "";
  const deviceFilter = state.filters.employeeDevice || "";
  const treeFilterActive = Boolean(search || assetSearch || statusFilter || orgFilter || deviceFilter);
  const filteredEmployees = getFilteredEmployees();

  const employeeIdSet = new Set(filteredEmployees.map((employee) => employee.id));
  const visibleOrgIds = getVisibleOrgIdsForEmployees(search, employeeIdSet, treeFilterActive);
  const rootOrgs = getRootOrgs().filter((org) => !treeFilterActive || visibleOrgIds.has(org.id));
  const unassignedEmployees = filteredEmployees.filter((employee) => !employee.orgId || !getOrg(employee.orgId));
  const directTreeCount = rootOrgs.length + (unassignedEmployees.length ? 1 : 0);
  const selectedCount = state.selectedEmployeeIds.length;

  return `
    <div class="page-intro">
      <div><h2>办公设备使用人员</h2><p>按组织架构树查看人员，节点下直接展示电脑、显示屏和非资产设备</p></div>
      <div class="toolbar-actions">
        <button class="secondary-button" data-action="select-all-employees">全选当前结果</button>
        <button class="secondary-button" data-action="clear-employee-selection">清空选择</button>
        <button class="secondary-button" data-action="export-employees" ${selectedCount ? "" : "disabled"}>导出选中 ${selectedCount}</button>
        <button class="primary-button" data-action="open-employee">＋ 新增人员</button>
      </div>
    </div>
    <div class="toolbar">
      <div class="toolbar-actions">
        <label class="search-box"><span>⌕</span><input data-filter="employees" value="${escapeHtml(
          employeeSearchDraftValue("employees"),
        )}" placeholder="搜索姓名、工号、部门或组织..." /></label>
        <label class="search-box employee-asset-search"><span>IT</span><input data-filter="employeeAssetSearch" value="${escapeHtml(
          employeeSearchDraftValue("employeeAssetSearch"),
        )}" placeholder="搜索 IT 物资品牌或型号..." /></label>
        <button class="secondary-button" data-action="apply-employee-search">搜索</button>
        <label class="select-box"><select data-filter="employeeStatus">
          <option value="">全部人员状态</option>
          ${["active", "inactive"]
            .map(
              (status) =>
                `<option value="${status}" ${statusFilter === status ? "selected" : ""}>${escapeHtml(
                  statusLabels[status],
                )}</option>`,
            )
            .join("")}
        </select></label>
        <label class="select-box employee-org-filter"><select data-filter="employeeOrg">
          <option value="">全部组织</option>
          ${getOrgSelectOptions()
            .map(
              (option) =>
                `<option value="${escapeHtml(option.value)}" ${
                  orgFilter === option.value ? "selected" : ""
                }>${escapeHtml(option.label)}</option>`,
            )
            .join("")}
          <option value="__unassigned__" ${orgFilter === "__unassigned__" ? "selected" : ""}>未分配组织</option>
        </select></label>
        <label class="select-box"><select data-filter="employeeDevice">
          <option value="">全部设备情况</option>
          <option value="assigned" ${deviceFilter === "assigned" ? "selected" : ""}>已分配设备</option>
          <option value="unassigned" ${deviceFilter === "unassigned" ? "selected" : ""}>无设备</option>
        </select></label>
        ${
          treeFilterActive
            ? '<button class="secondary-button" data-action="clear-employee-filters">清除筛选</button>'
            : ""
        }
      </div>
      <span class="secondary-text">显示 ${filteredEmployees.length} / ${state.employees.length} 人 · ${directTreeCount} 个顶层节点</span>
    </div>

    <div class="stats-grid compact">
      <div class="stat-card">
        <div class="stat-label"><span>组织总数</span><span class="stat-mark">⎇</span></div>
        <div class="stat-value">${state.orgs.length}</div>
        <div class="stat-foot">${getRootOrgs().length} 个根组织</div>
      </div>
      <div class="stat-card">
        <div class="stat-label"><span>在职人员</span><span class="stat-mark">♙</span></div>
        <div class="stat-value">${state.employees.filter((employee) => employee.status === "active").length}</div>
        <div class="stat-foot">支持设备直接维护</div>
      </div>
      <div class="stat-card">
        <div class="stat-label"><span>已分配电脑</span><span class="stat-mark">▣</span></div>
        <div class="stat-value">${state.computers.filter((computer) => computer.userId).length}</div>
        <div class="stat-foot">和人员树同步联动</div>
      </div>
      <div class="stat-card">
        <div class="stat-label"><span>未挂组织</span><span class="stat-mark">∅</span></div>
        <div class="stat-value">${state.employees.filter((employee) => !employee.orgId || !getOrg(employee.orgId)).length}</div>
        <div class="stat-foot">建议及时整理归属</div>
      </div>
    </div>

    <div class="tree-layout">
      <section class="section-block">
        <div class="section-heading">
          <div><h2>组织人员树</h2><span>组织可折叠，人员节点支持设备维护</span></div>
          <div class="toolbar-actions">
            <button class="secondary-button" data-action="expand-all-orgs">全部展开</button>
            <button class="secondary-button" data-action="collapse-all-orgs">全部收起</button>
          </div>
        </div>
        <div class="data-panel tree-panel">
          ${
            rootOrgs.length || unassignedEmployees.length
              ? `${rootOrgs
                  .map((org) => renderEmployeeOrgNode(org, { visibleOrgIds, employeeIdSet, searchActive: treeFilterActive }))
                  .join("")}
                 ${unassignedEmployees.length ? renderUnassignedEmployeeBlock(unassignedEmployees) : ""}`
              : '<div class="empty-state">暂无符合条件的人员记录</div>'
          }
        </div>
      </section>
    </div>
  `;
}

function getFilteredLeftEmployees() {
  const search = (state.filters.leftEmployees || "").trim().toLowerCase();
  return [...state.leftEmployees]
    .filter((employee) => {
      const searchText = [
        employee.employeeNo,
        employee.name,
        employee.orgPath,
        employee.department,
        employee.position,
        employee.leaveInfo,
        employee.leaveRemark,
      ]
        .join(" ")
        .toLowerCase();
      return !search || searchText.includes(search);
    })
    .sort((a, b) => {
      const dateCompare = String(b.leaveDate || b.archivedAt || "").localeCompare(String(a.leaveDate || a.archivedAt || ""));
      return dateCompare || compareText(a.employeeNo, b.employeeNo) || compareText(a.name, b.name);
    });
}

function renderLeftEmployeesPage() {
  const employees = getFilteredLeftEmployees();
  return `
    <div class="page-intro">
      <div><h2>离职人员</h2><p>离职人员会从组织树移出，并保留离职时间、离职说明、备注和离职时设备快照，点击详情可查看完整归档内容</p></div>
      <div class="toolbar-actions">
        <button class="secondary-button" data-action="navigate" data-page="employees">返回使用人员</button>
      </div>
    </div>
    <div class="toolbar">
      <div class="toolbar-actions">
        <label class="search-box"><span>⌕</span><input data-filter="leftEmployees" value="${escapeHtml(
          state.filters.leftEmployees || "",
        )}" placeholder="搜索姓名、编号、组织、部门或离职说明..." /></label>
      </div>
      <span class="secondary-text">显示 ${employees.length} / ${state.leftEmployees.length} 人</span>
    </div>
    <div class="data-panel">${renderLeftEmployeeTable(employees)}</div>
  `;
}

function renderLeftEmployeeTable(employees) {
  if (!employees.length) return '<div class="empty-state">暂无离职人员记录</div>';
  return `
    <div class="table-wrap">
      <table>
        <thead><tr><th>人员</th><th>原组织 / 部门</th><th>岗位</th><th>离职日期</th><th>离职设备快照</th><th>归档信息</th></tr></thead>
        <tbody>
          ${employees
            .map(
              (employee) => `<tr>
                <td><div class="primary-text">${escapeHtml(employee.name)}</div><div class="secondary-text mono">${escapeHtml(
                  employee.employeeNo,
                )}</div></td>
                <td><div class="primary-text">${escapeHtml(employee.orgPath || orgPathName(employee.orgId))}</div><div class="secondary-text">${escapeHtml(
                  employee.department || "未填写部门",
                )}</div></td>
                <td>${escapeHtml(employee.position || "—")}</td>
                <td>${escapeHtml(employee.leaveDate || "—")}</td>
                <td>${leftEmployeeDeviceChips(employee.devices || [])}</td>
                <td><button class="text-button" data-action="open-left-employee" data-id="${escapeHtml(
                  employee.id,
                )}">查看详情</button></td>
              </tr>`,
            )
            .join("")}
        </tbody>
      </table>
    </div>
  `;
}

function inventoryTreeRowsLegacy() {
  const nodes = buildInventoryTreeNodes();
  if (!nodes.length) return "";

  return nodes
    .map(({ type, brands }) => {
      const typeQuantity = brands.reduce(
        (sum, brand) =>
          sum + brand.models.reduce((brandSum, model) => brandSum + Math.max(0, Number(model.quantity || 0)), 0),
        0,
      );
      const typeModelCount = brands.reduce((sum, brand) => sum + brand.models.length, 0);
      return `
        <section class="inventory-node inventory-type-node">
          <div class="inventory-node-row">
            <div class="inventory-node-main">
              <strong>${escapeHtml(type.name)}</strong>
              <span>${brands.length} 个品牌 / ${typeModelCount} 个型号 / ${typeQuantity} ${escapeHtml(type.unit || "件")}</span>
            </div>
            <div class="inline-actions">
              <button class="text-button" data-action="open-type" data-id="${escapeHtml(type.id)}">编辑类型</button>
              <button class="text-button" data-action="open-inventory-brand" data-type-id="${escapeHtml(type.id)}">新增品牌</button>
              <button class="text-button danger" data-action="delete-type" data-id="${escapeHtml(type.id)}" ${
                isProtectedInventoryType(type) ? 'disabled title="系统保留类型不可删除"' : ""
              }>删除</button>
            </div>
          </div>
          <div class="inventory-children">
            ${
              brands.length
                ? brands
                    .map((brand) => {
                      const brandQuantity = brand.models.reduce(
                        (sum, model) => sum + Math.max(0, Number(model.quantity || 0)),
                        0,
                      );
                      return `
                        <div class="inventory-node inventory-brand-node">
                          <div class="inventory-node-row">
                            <div class="inventory-node-main">
                              <strong>${escapeHtml(brand.name)}</strong>
                              <span>${brand.models.length} 个型号 / ${brandQuantity} ${escapeHtml(type.unit || "件")}</span>
                            </div>
                            <div class="inline-actions">
                              <button class="text-button" data-action="open-inventory-brand" data-type-id="${escapeHtml(
                                type.id,
                              )}" data-id="${escapeHtml(brand.id)}">编辑品牌</button>
                              <button class="text-button" data-action="open-inventory-model" data-type-id="${escapeHtml(
                                type.id,
                              )}" data-brand-id="${escapeHtml(brand.id)}">新增型号</button>
                              <button class="text-button danger" data-action="delete-inventory-brand" data-id="${escapeHtml(
                                brand.id,
                              )}">删除</button>
                            </div>
                          </div>
                          <div class="inventory-model-list">
                            ${
                              brand.models.length
                                ? brand.models
                                    .map(
                                      (model) => {
                                        const modelMeta = inventoryModelDisplayMeta(type, model);
                                        return `
                                        <div class="inventory-model-row">
                                          <div><span>${escapeHtml(model.name)}</span><small>${escapeHtml(modelMeta)}</small></div>
                                          <div class="inline-actions">
                                            <button class="text-button" data-action="open-inventory-model" data-type-id="${escapeHtml(
                                              type.id,
                                            )}" data-brand-id="${escapeHtml(brand.id)}" data-id="${escapeHtml(
                                              model.id,
                                            )}">编辑</button>
                                            <button class="text-button danger" data-action="delete-inventory-model" data-id="${escapeHtml(
                                              model.id,
                                            )}">删除</button>
                                          </div>
                                        </div>
                                      `;
                                      },
                                    )
                                    .join("")
                                : '<div class="inventory-empty">当前没有型号记录</div>'
                            }
                          </div>
                        </div>
                      `;
                    })
                    .join("")
                : '<div class="inventory-empty">当前没有品牌记录</div>'
            }
          </div>
        </section>
      `;
    })
    .join("");
}

function renderInventoryPageLegacy() {
  const totalQuantity = state.inventoryModels.reduce(
    (sum, model) => sum + Math.max(0, Number(model.quantity || 0)),
    0,
  );
  const nodes = buildInventoryTreeNodes();
  const visibleBrandCount = nodes.reduce((sum, node) => sum + node.brands.length, 0);
  const visibleModelCount = nodes.reduce(
    (sum, node) => sum + node.brands.reduce((brandSum, brand) => brandSum + brand.models.length, 0),
    0,
  );
  const visibleQuantity = nodes.reduce(
    (sum, node) =>
      sum +
      node.brands.reduce(
        (brandSum, brand) =>
          brandSum + brand.models.reduce((modelSum, model) => modelSum + Math.max(0, Number(model.quantity || 0)), 0),
        0,
      ),
    0,
  );
  return `
    <div class="page-intro">
      <div><h2>IT物资</h2><p>按设备类型、品牌、型号管理未分配的显示屏、鼠标、键盘等办公物资库存。</p></div>
      <div class="toolbar-actions">
        <button class="secondary-button" data-action="open-inventory-import">＋ 导入物资</button>
        <button class="secondary-button" data-action="export-inventory">导出筛选</button>
        <button class="primary-button" data-action="open-type">新增类型</button>
        <button class="secondary-button" data-action="navigate" data-page="dashboard">返回工作台</button>
      </div>
    </div>
    <div class="toolbar">
      <div class="toolbar-actions">
        <label class="search-box"><span>⌕</span><input data-filter="inventorySearch" value="${escapeHtml(
          state.filters.inventorySearch || "",
        )}" placeholder="搜索类型、品牌或型号..." /></label>
        <label class="select-box"><select data-filter="inventoryType">
          ${inventoryTypeFilterOptions()
            .map(
              (option) =>
                `<option value="${escapeHtml(option.value)}" ${
                  (state.filters.inventoryType || "") === option.value ? "selected" : ""
                }>${escapeHtml(option.label)}</option>`,
            )
            .join("")}
        </select></label>
        <label class="select-box"><select data-filter="inventoryBrand">
          ${inventoryBrandFilterOptions(state.filters.inventoryType || "")
            .map(
              (option) =>
                `<option value="${escapeHtml(option.value)}" ${
                  (state.filters.inventoryBrand || "") === option.value ? "selected" : ""
                }>${escapeHtml(option.label)}</option>`,
            )
            .join("")}
        </select></label>
        ${
          state.filters.inventorySearch || state.filters.inventoryType || state.filters.inventoryBrand
            ? '<button class="secondary-button" data-action="clear-inventory-filters">清除筛选</button>'
            : ""
        }
      </div>
      <span class="secondary-text">显示 ${visibleModelCount} / ${state.inventoryModels.length} 个型号 · ${visibleBrandCount} / ${state.inventoryBrands.length} 个品牌 · ${visibleQuantity} / ${totalQuantity} 件</span>
    </div>
    <div class="stats-grid compact">
      <div class="stat-card"><div class="stat-label"><span>设备类型</span><span class="stat-mark">T</span></div><div class="stat-value">${
        state.nonAssetTypes.length
      }</div><div class="stat-foot">库存一级分组</div></div>
      <div class="stat-card"><div class="stat-label"><span>品牌组</span><span class="stat-mark">B</span></div><div class="stat-value">${
        state.inventoryBrands.length
      }</div><div class="stat-foot">库存二级分组</div></div>
      <div class="stat-card"><div class="stat-label"><span>型号组</span><span class="stat-mark">M</span></div><div class="stat-value">${
        state.inventoryModels.length
      }</div><div class="stat-foot">库存最下级条目</div></div>
      <div class="stat-card"><div class="stat-label"><span>可用数量</span><span class="stat-mark">Q</span></div><div class="stat-value">${totalQuantity}</div><div class="stat-foot">未分配库存总量</div></div>
    </div>
    <section class="section-block">
      <div class="section-heading"><div><h2>类型 / 品牌 / 型号 / 数量</h2><span>已分配到人员名下的物资不在此库存中体现。</span></div></div>
      <div class="data-panel inventory-panel">${inventoryTreeRows() || '<div class="empty-state">当前没有库存分组</div>'}</div>
    </section>
    <section class="section-block">
      <div class="section-heading">
        <div><h2>采购入库信息</h2><span>${state.inventoryPurchaseLogs.length} 条采购入库记录，普通物资不在库存型号上显示入库日期</span></div>
        <div class="toolbar-actions">
          <button class="secondary-button" data-action="export-inventory-purchase" ${
            state.inventoryPurchaseLogs.length ? "" : "disabled"
          }>导出入库表</button>
        </div>
      </div>
      <div class="data-panel">${renderInventoryPurchaseTable(state.inventoryPurchaseLogs)}</div>
    </section>
  `;
}

function inventoryTreeRows() {
  const nodes = buildInventoryTreeNodes();
  if (!nodes.length) return "";

  return nodes
    .map(({ type, brands }) => {
      const typeQuantity = brands.reduce(
        (sum, brand) =>
          sum + brand.models.reduce((brandSum, model) => brandSum + Math.max(0, Number(model.quantity || 0)), 0),
        0,
      );
      const typeModelCount = brands.reduce((sum, brand) => sum + brand.models.length, 0);
      const typeExpanded = isInventoryTypeExpanded(type.id);
      const brandRows = brands.length
        ? brands
            .map((brand) => {
              const brandQuantity = brand.models.reduce(
                (sum, model) => sum + Math.max(0, Number(model.quantity || 0)),
                0,
              );
              const brandExpanded = isInventoryBrandExpanded(brand.id);
              return `
                <div class="inventory-node inventory-brand-node">
                  <div class="inventory-node-row">
                    <div class="inventory-node-head">
                      <button class="tree-toggle inventory-toggle" data-action="toggle-inventory-brand" data-id="${escapeHtml(
                        brand.id,
                      )}" aria-expanded="${brandExpanded ? "true" : "false"}">${brandExpanded ? "-" : "+"}</button>
                      <div class="inventory-node-main">
                        <strong>${escapeHtml(brand.name)}</strong>
                        <span>${brand.models.length} 个型号 / ${brandQuantity} ${escapeHtml(type.unit || "件")}</span>
                      </div>
                    </div>
                    <div class="inline-actions">
                      <button class="text-button" data-action="open-inventory-brand" data-type-id="${escapeHtml(
                        type.id,
                      )}" data-id="${escapeHtml(brand.id)}">编辑品牌</button>
                      <button class="text-button" data-action="open-inventory-model" data-type-id="${escapeHtml(
                        type.id,
                      )}" data-brand-id="${escapeHtml(brand.id)}">新增型号</button>
                      <button class="text-button danger" data-action="delete-inventory-brand" data-id="${escapeHtml(
                        brand.id,
                      )}">删除</button>
                    </div>
                  </div>
                  ${
                    brandExpanded
                      ? `<div class="inventory-model-list">
                      ${
                        brand.models.length
                          ? brand.models
                              .map(
                                (model) => {
                                  const modelMeta = inventoryModelDisplayMeta(type, model);
                                  return `
                                  <div class="inventory-model-row">
                                    <div><span>${escapeHtml(model.name)}</span><small>${escapeHtml(modelMeta)}</small></div>
                                    <div class="inline-actions">
                                      <button class="text-button" data-action="open-inventory-model" data-type-id="${escapeHtml(
                                        type.id,
                                      )}" data-brand-id="${escapeHtml(brand.id)}" data-id="${escapeHtml(
                                        model.id,
                                      )}">编辑</button>
                                      <button class="text-button danger" data-action="delete-inventory-model" data-id="${escapeHtml(
                                        model.id,
                                      )}">删除</button>
                                    </div>
                                  </div>
                                `;
                                },
                              )
                              .join("")
                          : '<div class="inventory-empty">当前没有型号记录</div>'
                      }
                    </div>`
                      : ""
                  }
                </div>
              `;
            })
            .join("")
        : '<div class="inventory-empty">当前没有品牌记录</div>';

      return `
        <section class="inventory-node inventory-type-node">
          <div class="inventory-node-row">
            <div class="inventory-node-head">
              <button class="tree-toggle inventory-toggle" data-action="toggle-inventory-type" data-id="${escapeHtml(
                type.id,
              )}" aria-expanded="${typeExpanded ? "true" : "false"}">${typeExpanded ? "-" : "+"}</button>
              <div class="inventory-node-main">
                <strong>${escapeHtml(type.name)}</strong>
                <span>${brands.length} 个品牌 / ${typeModelCount} 个型号 / ${typeQuantity} ${escapeHtml(type.unit || "件")}</span>
              </div>
            </div>
            <div class="inline-actions">
              <button class="text-button" data-action="open-type" data-id="${escapeHtml(type.id)}">编辑类型</button>
              <button class="text-button" data-action="open-inventory-brand" data-type-id="${escapeHtml(type.id)}">新增品牌</button>
              <button class="text-button danger" data-action="delete-type" data-id="${escapeHtml(type.id)}" ${
                isProtectedInventoryType(type) ? 'disabled title="系统保留类型不可删除"' : ""
              }>删除</button>
            </div>
          </div>
          ${typeExpanded ? `<div class="inventory-children">${brandRows}</div>` : ""}
        </section>
      `;
    })
    .join("");
}

function renderInventoryPage() {
  const totalQuantity = state.inventoryModels.reduce(
    (sum, model) => sum + Math.max(0, Number(model.quantity || 0)),
    0,
  );
  const nodes = buildInventoryTreeNodes();
  const visibleBrandCount = nodes.reduce((sum, node) => sum + node.brands.length, 0);
  const visibleModelCount = nodes.reduce(
    (sum, node) => sum + node.brands.reduce((brandSum, brand) => brandSum + brand.models.length, 0),
    0,
  );
  const visibleQuantity = nodes.reduce(
    (sum, node) =>
      sum +
      node.brands.reduce(
        (brandSum, brand) =>
          brandSum + brand.models.reduce((modelSum, model) => modelSum + Math.max(0, Number(model.quantity || 0)), 0),
        0,
      ),
    0,
  );
  return `
    <div class="page-intro">
      <div><h2>IT物资</h2><p>按设备类型、品牌、型号管理未分配的显示屏、鼠标、键盘等办公物资库存。</p></div>
      <div class="toolbar-actions">
        <button class="secondary-button" data-action="open-inventory-import">＋ 导入物资</button>
        <button class="secondary-button" data-action="export-inventory">导出筛选</button>
        <button class="primary-button" data-action="open-type">新增类型</button>
        <button class="secondary-button" data-action="navigate" data-page="dashboard">返回工作台</button>
      </div>
    </div>
    <div class="toolbar">
      <div class="toolbar-actions">
        <label class="search-box"><span>⌕</span><input data-filter="inventorySearch" value="${escapeHtml(
          state.filters.inventorySearch || "",
        )}" placeholder="搜索类型、品牌或型号..." /></label>
        <label class="select-box"><select data-filter="inventoryType">
          ${inventoryTypeFilterOptions()
            .map(
              (option) =>
                `<option value="${escapeHtml(option.value)}" ${
                  (state.filters.inventoryType || "") === option.value ? "selected" : ""
                }>${escapeHtml(option.label)}</option>`,
            )
            .join("")}
        </select></label>
        <label class="select-box"><select data-filter="inventoryBrand">
          ${inventoryBrandFilterOptions(state.filters.inventoryType || "")
            .map(
              (option) =>
                `<option value="${escapeHtml(option.value)}" ${
                  (state.filters.inventoryBrand || "") === option.value ? "selected" : ""
                }>${escapeHtml(option.label)}</option>`,
            )
            .join("")}
        </select></label>
        ${
          state.filters.inventorySearch || state.filters.inventoryType || state.filters.inventoryBrand
            ? '<button class="secondary-button" data-action="clear-inventory-filters">清除筛选</button>'
            : ""
        }
      </div>
      <span class="secondary-text">显示 ${visibleModelCount} / ${state.inventoryModels.length} 个型号 · ${visibleBrandCount} / ${state.inventoryBrands.length} 个品牌 · ${visibleQuantity} / ${totalQuantity} 件</span>
    </div>
    <div class="stats-grid compact">
      <div class="stat-card"><div class="stat-label"><span>设备类型</span><span class="stat-mark">T</span></div><div class="stat-value">${
        state.nonAssetTypes.length
      }</div><div class="stat-foot">库存一级分组</div></div>
      <div class="stat-card"><div class="stat-label"><span>品牌组</span><span class="stat-mark">B</span></div><div class="stat-value">${
        state.inventoryBrands.length
      }</div><div class="stat-foot">库存二级分组</div></div>
      <div class="stat-card"><div class="stat-label"><span>型号组</span><span class="stat-mark">M</span></div><div class="stat-value">${
        state.inventoryModels.length
      }</div><div class="stat-foot">库存最下级条目</div></div>
      <div class="stat-card"><div class="stat-label"><span>可用数量</span><span class="stat-mark">Q</span></div><div class="stat-value">${totalQuantity}</div><div class="stat-foot">未分配库存总量</div></div>
    </div>
    <section class="section-block">
      <div class="section-heading">
        <div><h2>类型 / 品牌 / 型号 / 数量</h2><span>已分配到人员名下的物资不在此库存中体现。</span></div>
        <div class="toolbar-actions inventory-tree-actions">
          <button class="secondary-button" data-action="expand-all-inventory" ${nodes.length ? "" : "disabled"}>展开全部</button>
          <button class="secondary-button" data-action="collapse-all-inventory" ${nodes.length ? "" : "disabled"}>收起全部</button>
        </div>
      </div>
      <div class="data-panel inventory-panel">${inventoryTreeRows() || '<div class="empty-state">当前没有库存分组</div>'}</div>
    </section>
    <section class="section-block">
      <div class="section-heading">
        <div><h2>采购入库信息</h2><span>${state.inventoryPurchaseLogs.length} 条采购入库记录，普通物资不在库存型号上显示入库日期</span></div>
        <div class="toolbar-actions">
          <button class="secondary-button" data-action="export-inventory-purchase" ${
            state.inventoryPurchaseLogs.length ? "" : "disabled"
          }>导出入库表</button>
        </div>
      </div>
      <div class="data-panel">${renderInventoryPurchaseTable(state.inventoryPurchaseLogs)}</div>
    </section>
  `;
}

function isComputerPurchaseLog(log) {
  const type = log?.typeId ? getType(log.typeId) : null;
  return isComputerInventoryType(type) || isComputerInventoryTypeName(log?.typeName || "");
}

function sortInventoryPurchaseLogs(logs) {
  return [...logs].sort((a, b) =>
    String(b.inboundDate || b.createdAt || "").localeCompare(String(a.inboundDate || a.createdAt || "")),
  );
}

function renderInventoryPurchaseNoteEditor(log) {
  return `
    <form class="purchase-note-editor" data-form="inventory-purchase-note" data-id="${escapeHtml(log.id)}">
      <input
        class="purchase-note-input"
        type="text"
        name="note"
        maxlength="500"
        value="${escapeHtml(log.note || "")}"
        placeholder="填写备注"
        aria-label="采购入库备注"
      />
      <button class="text-button purchase-note-save" type="submit">保存</button>
    </form>
  `;
}

function renderInventoryPurchaseRows(rows, computer = false) {
  return rows
    .map((log) => {
      if (computer) {
        return `<tr>
          <td class="audit-time">${escapeHtml(log.inboundDate || "—")}</td>
          <td>${escapeHtml(log.brandName || "—")}</td>
          <td class="primary-text purchase-model">${escapeHtml(log.modelName || "—")}</td>
          <td>${escapeHtml(log.quantity)}</td>
          <td>${escapeHtml(log.cpu || "—")}</td>
          <td>${escapeHtml(log.memory || "—")}</td>
          <td>${escapeHtml(log.storage || "—")}</td>
          <td>${escapeHtml(log.gpu || "—")}</td>
          <td>${escapeHtml(log.sourceLabel || "—")}</td>
          <td>${renderInventoryPurchaseNoteEditor(log)}</td>
        </tr>`;
      }
      return `<tr>
        <td class="audit-time">${escapeHtml(log.inboundDate || "—")}</td>
        <td>${escapeHtml(log.typeName || "—")}</td>
        <td>${escapeHtml(log.brandName || "—")}</td>
        <td class="primary-text purchase-model">${escapeHtml(log.modelName || "—")}</td>
        <td>${escapeHtml(log.quantity)}</td>
        <td>${escapeHtml(log.sourceLabel || "—")}</td>
        <td>${renderInventoryPurchaseNoteEditor(log)}</td>
      </tr>`;
    })
    .join("");
}

function renderInventoryPurchaseTable(logs) {
  if (!logs.length) return '<div class="empty-state">暂无采购入库信息</div>';
  const sortedLogs = sortInventoryPurchaseLogs(logs);
  const standardLogs = sortedLogs.filter((log) => !isComputerPurchaseLog(log));
  const computerLogs = sortedLogs.filter((log) => isComputerPurchaseLog(log));
  const sections = [];

  if (standardLogs.length) {
    sections.push(`
      <section class="purchase-table-group">
        <div class="purchase-table-heading">
          <strong>普通物资入库</strong>
          <span>${standardLogs.length} 条记录</span>
        </div>
        <div class="table-wrap">
          <table class="audit-table purchase-table purchase-table-standard">
            <thead><tr><th>入库时间</th><th>物资类型</th><th>品牌</th><th>型号</th><th>数量</th><th>来源</th><th>备注</th></tr></thead>
            <tbody>${renderInventoryPurchaseRows(standardLogs)}</tbody>
          </table>
        </div>
      </section>
    `);
  }

  if (computerLogs.length) {
    sections.push(`
      <section class="purchase-table-group">
        <div class="purchase-table-heading">
          <strong>电脑入库</strong>
          <span>${computerLogs.length} 条记录</span>
        </div>
        <div class="table-wrap">
          <table class="audit-table purchase-table purchase-table-computer">
            <thead><tr><th>入库时间</th><th>品牌</th><th>型号</th><th>数量</th><th>CPU</th><th>内存</th><th>存储</th><th>显卡</th><th>来源</th><th>备注</th></tr></thead>
            <tbody>${renderInventoryPurchaseRows(computerLogs, true)}</tbody>
          </table>
        </div>
      </section>
    `);
  }

  return sections.join("");
}

function renderInventoryMovementTable(logs) {
  if (!logs.length) return '<div class="empty-state">暂无 IT 物资变动日志</div>';
  return `
    <div class="table-wrap">
      <table class="audit-table">
        <thead><tr><th>时间</th><th>增减</th><th>物资</th><th>数量</th><th>来源</th><th>流向</th><th>标注</th><th>操作</th></tr></thead>
        <tbody>
          ${logs
            .map(
              (log) => `<tr>
                <td class="audit-time">${escapeHtml(formatDateTime(log.occurredAt))}</td>
                <td><span class="audit-action ${inventoryDirectionClass(log.direction)}">${escapeHtml(
                  inventoryDirectionLabel(log.direction),
                )}</span></td>
                <td><div class="primary-text">${escapeHtml(log.typeName || "未分类物资")}</div><div class="secondary-text">${escapeHtml(
                  [log.brandName, log.modelName].filter(Boolean).join(" / ") || "未填写品牌型号",
                )}</div></td>
                <td>${escapeHtml(log.quantity)}</td>
                <td>${escapeHtml(log.sourceLabel || "—")}</td>
                <td>${escapeHtml(log.targetLabel || "—")}</td>
                <td><span class="audit-summary">${escapeHtml(log.note || "—")}</span></td>
                <td><button class="text-button" data-action="edit-inventory-log-note" data-id="${escapeHtml(log.id)}">标注</button></td>
              </tr>`,
            )
            .join("")}
        </tbody>
      </table>
    </div>
  `;
}

function openInventoryBrandModal(typeId, id = "") {
  const type = getType(typeId);
  if (!type) return;
  const existing = getInventoryBrand(id);
  const brand = existing || { id: "", typeId, name: "", sortOrder: 1000 };
  openModal(
    `${modalHeader(id ? "编辑库存品牌" : "新增库存品牌", `${type.name} / 品牌分组`)}
      <form data-form="inventory-brand" data-id="${escapeHtml(brand.id)}" data-type-id="${escapeHtml(type.id)}">
        <div class="form-grid">${inputField("品牌名称", "name", brand.name, true, "罗技")}${inputField(
          "排序",
          "sortOrder",
          brand.sortOrder || 1000,
          true,
          "1000",
          "number",
          "0",
        )}</div>
        <div class="modal-footer"><button type="button" class="secondary-button" data-action="close-modal">取消</button><button class="primary-button" type="submit">保存品牌</button></div>
      </form>`,
  );
}

function openInventoryModelModal(typeId, brandId, id = "") {
  const type = getType(typeId);
  const brand = getInventoryBrand(brandId);
  if (!type || !brand) return;
  const computerModel = isComputerInventoryType(type);
  const existing = getInventoryModel(id);
  const model = existing || {
    id: "",
    typeId,
    brandId,
    name: "",
    quantity: 0,
    inboundDate: computerModel ? currentDateText() : "",
    cpu: "",
    memory: "",
    storage: "",
    gpu: "",
    sortOrder: 1000,
  };
  openModal(
    `${modalHeader(id ? "编辑库存型号" : "新增库存型号", `${type.name} / ${brand.name}`)}
      <form data-form="inventory-model" data-id="${escapeHtml(model.id)}" data-type-id="${escapeHtml(
        type.id,
      )}" data-brand-id="${escapeHtml(brand.id)}">
        <div class="form-grid">${inputField("型号", "name", model.name, true, "M332")}${inputField(
          "可用数量",
          "quantity",
          Math.max(0, Number(model.quantity || 0)),
          true,
          "0",
          "number",
          "0",
          "0",
        )}${computerModel ? `${inputField(
          "入库时间",
          "inboundDate",
          model.inboundDate || (id ? "" : currentDateText()),
          true,
          "",
          "date",
        )}${inputField(
          "CPU",
          "cpu",
          model.cpu || "",
          false,
          "i5-14500HX",
        )}${inputField("内存", "memory", model.memory || "", false, "16G")}${inputField(
          "存储",
          "storage",
          model.storage || "",
          false,
          "512G",
        )}${inputField("显卡", "gpu", model.gpu || "", false, "RTX4060TI")}` : ""}${inputField(
          "排序",
          "sortOrder",
          model.sortOrder || 1000,
          true,
          "1000",
          "number",
          "0",
        )}</div>
        <div class="modal-footer"><button type="button" class="secondary-button" data-action="close-modal">取消</button><button class="primary-button" type="submit">保存型号</button></div>
      </form>`,
  );
}

function findInventoryTypeByName(name) {
  const target = inventoryText(name);
  return state.nonAssetTypes.find((type) => inventoryText(type.name) === target || inventoryText(type.code) === target);
}

function findInventoryBrandByName(typeId, name) {
  const target = inventoryText(name);
  return inventoryBrandsForType(typeId).find((brand) => inventoryText(brand.name) === target);
}

function findInventoryModelByName(brandId, name) {
  const target = inventoryText(name);
  return inventoryModelsForBrand(brandId).find((model) => inventoryText(model.name) === target);
}

function renderInventoryImportComputerFields(typeName = "") {
  const visible = isComputerInventoryTypeName(typeName);
  const disabledAttr = visible ? "" : "disabled";
  return `
    <div class="form-grid" data-inventory-computer-config ${visible ? "" : "hidden"}>
      ${inputField("CPU", "cpu", "", false, "i5-14500HX", "text", "", disabledAttr)}
      ${inputField("内存", "memory", "", false, "16G", "text", "", disabledAttr)}
      ${inputField("存储", "storage", "", false, "512G", "text", "", disabledAttr)}
      ${inputField("显卡", "gpu", "", false, "RTX4060TI", "text", "", disabledAttr)}
    </div>
  `;
}

function toggleInventoryImportComputerFields(form) {
  if (!form || form.dataset.form !== "inventory-import") return;
  const panel = form.querySelector("[data-inventory-computer-config]");
  if (!panel) return;
  const visible = isComputerInventoryTypeName(form.elements.type?.value || "");
  panel.hidden = !visible;
  panel.querySelectorAll("input, select, textarea").forEach((field) => {
    field.disabled = !visible;
  });
  if (visible && form.elements.inboundDate && !form.elements.inboundDate.value) {
    form.elements.inboundDate.value = currentDateText();
  }
}

function openInventoryImportModal() {
  const type = state.nonAssetTypes.find((item) => item.id === state.filters.inventoryType) || null;
  openModal(
    `${modalHeader("导入IT物资", "输入类型、品牌、型号和数量，已有项目会自动归类到对应层级，不存在则自动创建")}
      <form data-form="inventory-import">
        <div class="form-grid">
          ${inputField("设备类型", "type", type?.name || "", true, "鼠标")}
          ${inputField("品牌", "brand", "", true, "罗技")}
          ${inputField("型号", "model", "", true, "M330")}
          ${inputField("数量", "quantity", 1, true, "1", "number", "1")}
          ${inputField("入库时间", "inboundDate", currentDateText(), true, "", "date")}
        </div>
        ${renderInventoryImportComputerFields(type?.name || "")}
        ${textareaField("备注", "note", "", false, "如采购入库、盘点回库、临时补货等，可作为来源日志标注", 3)}
        <div class="modal-footer">
          <button type="button" class="secondary-button" data-action="close-modal">取消</button>
          <button class="primary-button" type="submit">导入物资</button>
        </div>
      </form>`,
  );
}

function openInventoryMovementNoteModal(id) {
  const log = state.inventoryMovementLogs.find((item) => item.id === id);
  if (!log) return;
  openModal(
    `${modalHeader("编辑物资标注", `${log.typeName} / ${[log.brandName, log.modelName].filter(Boolean).join(" / ")}`)}
      <form data-form="inventory-log-note" data-id="${escapeHtml(log.id)}">
        ${textareaField("标注", "note", log.note || "", false, "补充来源、流向或处理说明", 4)}
        <div class="modal-footer">
          <button type="button" class="secondary-button" data-action="close-modal">取消</button>
          <button class="primary-button" type="submit">保存标注</button>
        </div>
      </form>`,
  );
}

function handleInventoryMovementNoteSubmit(form) {
  const log = state.inventoryMovementLogs.find((item) => item.id === form.dataset.id);
  if (!log) return;
  const data = Object.fromEntries(new FormData(form).entries());
  log.note = String(data.note || "").trim();
  persistState(true);
  closeModal();
  render();
  showToast("物资标注已保存");
}

function handleInventoryPurchaseNoteSubmit(form) {
  const log = state.inventoryPurchaseLogs.find((item) => item.id === form.dataset.id);
  if (!log) return;
  const data = Object.fromEntries(new FormData(form).entries());
  const note = String(data.note || "").trim();
  if (note === String(log.note || "").trim()) {
    showToast("备注未发生变化");
    return;
  }
  log.note = note;
  persistState(true);
  showToast("采购入库备注已保存");
}

function getVisibleOrgIdsForEmployees(search, employeeIdSet, treeFilterActive = false) {
  const orgFilter = state.filters.employeeOrg || "";
  if (!treeFilterActive) {
    return new Set(state.orgs.map((org) => org.id));
  }

  const visible = new Set();
  if (orgFilter && orgFilter !== "__unassigned__" && getOrg(orgFilter)) {
    addOrgWithAncestors(visible, orgFilter);
    addOrgWithDescendants(visible, orgFilter);
  }

  state.orgs.forEach((org) => {
    const orgText = `${org.code} ${org.name} ${orgPathName(org.id)}`.toLowerCase();
    if (search && orgText.includes(search)) {
      addOrgWithAncestors(visible, org.id);
      addOrgWithDescendants(visible, org.id);
    }
  });

  state.employees.forEach((employee) => {
    if (employeeIdSet.has(employee.id) && employee.orgId && getOrg(employee.orgId)) {
      addOrgWithAncestors(visible, employee.orgId);
    }
  });

  return visible;
}

function addOrgWithAncestors(bucket, orgId) {
  let current = getOrg(orgId);
  const visited = new Set();
  while (current && !visited.has(current.id)) {
    visited.add(current.id);
    bucket.add(current.id);
    current = current.parentId ? getOrg(current.parentId) : null;
  }
}

function addOrgWithDescendants(bucket, orgId) {
  bucket.add(orgId);
  getDescendantOrgIds(orgId).forEach((childId) => bucket.add(childId));
}

function renderEmployeeOrgNode(org, context) {
  const depth = getOrgDepth(org.id);
  const children = getOrgChildren(org.id).filter((child) => !context.searchActive || context.visibleOrgIds.has(child.id));
  const directEmployees = sortEmployees(
    state.employees.filter(
      (employee) => employee.orgId === org.id && (!context.searchActive || context.employeeIdSet.has(employee.id)),
    ),
  );
  const hasVisibleBody = directEmployees.length || children.length;
  const expanded = context.searchActive ? true : isOrgExpanded(org.id);
  const summary = getOrgSummary(org.id);

  if (context.searchActive && !context.visibleOrgIds.has(org.id) && !hasVisibleBody) {
    return "";
  }

  return `
    <section class="tree-node" style="--tree-depth:${depth}">
      <div class="tree-node-header">
        <button class="tree-toggle" data-action="toggle-org" data-id="${escapeHtml(org.id)}" aria-expanded="${
          expanded ? "true" : "false"
        }" title="${expanded ? "收起部门" : "展开部门"}">${expanded ? "▾" : "▸"}</button>
        <div class="tree-node-main">
          <div class="tree-node-title"><span>${escapeHtml(org.name)}</span><span class="tree-node-code">${escapeHtml(
            org.code,
          )}</span></div>
          <div class="tree-node-meta">排序 ${escapeHtml(org.sortOrder)} · ${summary.employees} 人 · ${summary.computers} 台电脑 · ${escapeHtml(
            orgPathName(org.id),
          )}</div>
        </div>
        <div class="inline-actions">
          <button class="text-button" data-action="open-employee" data-org-id="${escapeHtml(org.id)}">新增人员</button>
          <button class="text-button" data-action="open-org" data-id="${escapeHtml(org.id)}" data-parent-id="${escapeHtml(
            org.parentId || "",
          )}">编辑组织</button>
          <button class="text-button" data-action="open-org" data-parent-id="${escapeHtml(org.id)}">新增下级</button>
        </div>
      </div>
      ${
        expanded
          ? `<div class="tree-node-body">
              ${directEmployees.map((employee) => renderEmployeeTreeRow(employee)).join("")}
              ${children.map((child) => renderEmployeeOrgNode(child, context)).join("")}
              ${!hasVisibleBody ? '<div class="tree-empty">当前组织下暂无人员</div>' : ""}
            </div>`
          : ""
      }
    </section>
  `;
}

function renderEmployeeTreeRow(employee) {
  return `
    <article class="employee-tree-row">
      <div class="employee-tree-selector">
        <input type="checkbox" class="row-selector" data-action="toggle-employee-selection" data-id="${escapeHtml(
          employee.id,
        )}" ${state.selectedEmployeeIds.includes(employee.id) ? "checked" : ""} title="选择人员" />
      </div>
      <div class="employee-tree-main">
        <div class="employee-tree-head">
          <div>
            <button class="employee-tree-title employee-tree-title-button" data-action="open-employee" data-id="${escapeHtml(
              employee.id,
            )}" title="查看人员信息">${escapeHtml(employee.name)} <span class="employee-tree-code">${escapeHtml(
              employee.employeeNo,
            )}</span></button>
            <div class="employee-tree-meta">${escapeHtml(
              `${orgName(employee.orgId)} · ${employee.department || "未填写部门"} · ${employee.position || "未填写岗位"}`,
            )}</div>
          </div>
          <div class="employee-tree-status">${statusPill(employee.status)}</div>
        </div>
        <div class="employee-tree-devices">${deviceChips(employee)}</div>
      </div>
      <div class="inline-actions">
        <button class="text-button" data-action="manage-devices" data-id="${escapeHtml(employee.id)}">设备</button>
        <button class="text-button" data-action="open-employee" data-id="${escapeHtml(employee.id)}">编辑</button>
        <button class="text-button danger" data-action="delete-employee" data-id="${escapeHtml(employee.id)}">删除</button>
      </div>
    </article>
  `;
}

function renderUnassignedEmployeeBlock(employees) {
  return `
    <section class="tree-node tree-node-unassigned" style="--tree-depth:0">
      <div class="tree-node-header">
        <button class="tree-toggle is-placeholder">•</button>
        <div class="tree-node-main">
          <div class="tree-node-title"><span>未分配组织</span><span class="tree-node-code">UNASSIGNED</span></div>
          <div class="tree-node-meta">${employees.length} 人</div>
        </div>
      </div>
      <div class="tree-node-body">
        ${employees.map((employee) => renderEmployeeTreeRow(employee)).join("")}
      </div>
    </section>
  `;
}

function renderEmployeeTable(employees, withActions) {
  if (!employees.length) return '<div class="empty-state">暂无符合条件的人员记录</div>';
  return `
    <div class="table-wrap">
      <table>
        <thead><tr><th>人员</th><th>组织 / 部门</th><th>岗位</th><th>办公设备清单</th><th>状态</th>${withActions ? "<th>操作</th>" : ""}</tr></thead>
        <tbody>
          ${employees
            .map(
              (employee) => `<tr>
                <td><div class="primary-text">${escapeHtml(employee.name)}</div><div class="secondary-text mono">${escapeHtml(
                  employee.employeeNo,
                )}</div></td>
                <td><div class="primary-text">${escapeHtml(orgName(employee.orgId))}</div><div class="secondary-text">${escapeHtml(
                  orgPathName(employee.orgId),
                )}</div></td>
                <td>${escapeHtml(employee.position || "—")}</td>
                <td>${deviceChips(employee)}</td>
                <td>${statusPill(employee.status)}</td>
                ${
                  withActions
                    ? `<td><div class="inline-actions">
                        <button class="text-button" data-action="manage-devices" data-id="${escapeHtml(employee.id)}">设备</button>
                        <button class="text-button" data-action="open-employee" data-id="${escapeHtml(employee.id)}">编辑</button>
                        <button class="text-button danger" data-action="delete-employee" data-id="${escapeHtml(employee.id)}">删除</button>
                      </div></td>`
                    : ""
                }
              </tr>`,
            )
            .join("")}
        </tbody>
      </table>
    </div>
  `;
}

function renderDictionaryPage() {
  const search = (state.filters.dictionary || "").trim().toLowerCase();
  const visibleOrgIds = getVisibleOrgIdsForDictionary(search);
  const visibleRoots = getRootOrgs().filter((org) => !search || visibleOrgIds.has(org.id));
  const types = state.nonAssetTypes.filter((type) => `${type.code} ${type.name}`.toLowerCase().includes(search));

  return `
    <div class="page-intro">
      <div><h2>基础字典</h2><p>组织树结构与人员页面共享同一套层级和排序规则</p></div>
      <div class="toolbar-actions">
        <button class="secondary-button" data-action="open-type">＋ 新增设备类型</button>
        <button class="primary-button" data-action="open-org">＋ 新增根组织</button>
      </div>
    </div>
    <div class="toolbar">
      <label class="search-box"><span>⌕</span><input data-filter="dictionary" value="${escapeHtml(
        state.filters.dictionary || "",
      )}" placeholder="搜索组织编码、组织名称或设备类型..." /></label>
    </div>
    <div class="dictionary-grid">
      <section class="section-block">
        <div class="section-heading"><div><h2>组织架构树</h2><span>${state.orgs.length} 个组织</span></div></div>
        <div class="data-panel tree-panel">
          ${
            visibleRoots.length
              ? visibleRoots.map((org) => renderDictionaryOrgNode(org, { visibleOrgIds, searchActive: Boolean(search) })).join("")
              : '<div class="empty-state">暂无符合条件的组织</div>'
          }
        </div>
      </section>
      <section class="section-block">
        <div class="section-heading"><div><h2>非资产设备类型</h2><span>${types.length} 个类型</span></div></div>
        <div class="data-panel">${renderTypeTable(types)}</div>
      </section>
    </div>
  `;
}

function getVisibleOrgIdsForDictionary(search) {
  if (!search) return new Set(state.orgs.map((org) => org.id));
  const visible = new Set();
  state.orgs.forEach((org) => {
    const text = `${org.code} ${org.name} ${orgPathName(org.id)}`.toLowerCase();
    if (text.includes(search)) {
      addOrgWithAncestors(visible, org.id);
      addOrgWithDescendants(visible, org.id);
    }
  });
  return visible;
}

function renderDictionaryOrgNode(org, context) {
  const depth = getOrgDepth(org.id);
  const children = getOrgChildren(org.id).filter((child) => !context.searchActive || context.visibleOrgIds.has(child.id));
  const expanded = context.searchActive ? true : isOrgExpanded(org.id);
  const summary = getOrgSummary(org.id);

  return `
    <section class="tree-node" style="--tree-depth:${depth}">
      <div class="tree-node-header">
        <button class="tree-toggle" data-action="toggle-org" data-id="${escapeHtml(org.id)}" aria-expanded="${
          expanded ? "true" : "false"
        }" title="${expanded ? "收起组织" : "展开组织"}">${expanded ? "▾" : "▸"}</button>
        <div class="tree-node-main">
          <div class="tree-node-title"><span>${escapeHtml(org.name)}</span><span class="tree-node-code">${escapeHtml(
            org.code,
          )}</span></div>
          <div class="tree-node-meta">排序 ${escapeHtml(org.sortOrder)} · ${summary.employees} 人 · ${summary.computers} 台电脑 · ${
            summary.children
          } 个下级</div>
        </div>
        <div class="inline-actions">
          <button class="text-button" data-action="open-org" data-parent-id="${escapeHtml(org.id)}">新增下级</button>
          <button class="text-button" data-action="open-org" data-id="${escapeHtml(org.id)}">编辑</button>
          <button class="text-button danger" data-action="delete-org" data-id="${escapeHtml(org.id)}">删除</button>
        </div>
      </div>
      ${
        expanded
          ? `<div class="tree-node-body">
              ${children.map((child) => renderDictionaryOrgNode(child, context)).join("")}
              ${
                !children.length
                  ? `<div class="tree-empty">组织路径：${escapeHtml(orgPathName(org.id))}</div>`
                  : ""
              }
            </div>`
          : ""
      }
    </section>
  `;
}

function renderTypeTable(types) {
  if (!types.length) return '<div class="empty-state">暂无符合条件的设备类型</div>';
  return `<div class="table-wrap"><table><thead><tr><th>编码</th><th>名称</th><th>计量单位</th><th>引用人数</th><th>操作</th></tr></thead><tbody>
    ${types
      .map((type) => {
        const usageCount = state.employees.filter((employee) =>
          getNonAssetItems(employee).some((item) => item.typeId === type.id && Number(item.quantity) > 0),
        ).length;
        return `<tr>
          <td class="mono">${escapeHtml(type.code)}</td>
          <td class="primary-text">${escapeHtml(type.name)}</td>
          <td>${escapeHtml(type.unit || "件")}</td>
          <td>${usageCount}</td>
          <td><div class="inline-actions">
            <button class="text-button" data-action="open-type" data-id="${escapeHtml(type.id)}">编辑</button>
            <button class="text-button danger" data-action="delete-type" data-id="${escapeHtml(type.id)}" ${
              isProtectedInventoryType(type) ? 'disabled title="系统保留类型不可删除"' : ""
            }>删除</button>
          </div></td>
        </tr>`;
      })
      .join("")}
  </tbody></table></div>`;
}

function openModal(content, wide = false) {
  document.body.classList.add("modal-open");
  document.querySelector("#modalRoot").innerHTML = `<div class="modal-backdrop" data-action="close-modal">
    <aside class="modal-panel ${wide ? "wide" : ""}" role="dialog" aria-modal="true">${content}</aside>
  </div>`;
}

function closeModal() {
  document.body.classList.remove("modal-open");
  document.querySelector("#modalRoot").innerHTML = "";
}

function modalHeader(title, description) {
  return `<div class="modal-header"><div><h2>${escapeHtml(title)}</h2><p>${escapeHtml(description)}</p></div><button class="close-button" data-action="close-modal" title="关闭">×</button></div>`;
}

function openComputerModal(id = "") {
  const computer = state.computers.find((item) => item.id === id) || {
    id: "",
    deviceName: "",
    orgId: state.orgs[0]?.id || "",
    deviceType: "laptop",
    brand: "",
    model: "",
    inventoryModelId: "",
    cpu: "",
    memory: "",
    storage: "",
    gpu: "",
    fixedAssetCode: "",
    purchaseDate: "",
    registeredDate: "",
    snSt: "",
    wifiMac: "",
    ethernetMac: "",
    location: "",
    department: "",
    status: "idle",
    userId: "",
  };
  const isEditing = Boolean(id);
  openModal(
    `${modalHeader(isEditing ? "编辑办公电脑" : "新增办公电脑", "登记设备基础信息、资产信息和当前使用人")}
      <form data-form="computer" data-id="${escapeHtml(computer.id)}">
        <section class="modal-section">
          <div class="form-grid three">
            ${inputField("设备名", "deviceName", computer.deviceName, true, "PC-IT-0001")}
            ${selectField(
              "设备类型",
              "deviceType",
              computer.deviceType,
              Object.entries(deviceTypeLabels).map(([value, label]) => ({ value, label })),
              true,
            )}
            ${selectField(
              "IT 资产状态",
              "status",
              computer.status,
              ["in_use", "idle", "repair", "retired", "lost"].map((value) => ({
                value,
                label: statusLabels[value],
              })),
              true,
            )}
            ${renderComputerInventorySelectionFields(computer)}
            ${selectField(
              "所属组织",
              "orgId",
              computer.orgId,
              getOrgSelectOptions({ includeBlank: true }),
              false,
            )}
          </div>
        </section>
        <section class="modal-section">
          <div class="form-grid three">
            ${inputField("CPU", "cpu", computer.cpu, false, "Intel Core i5-12400")}
            ${inputField("内存", "memory", computer.memory, false, "16GB")}
            ${inputField("存储", "storage", computer.storage, false, "512GB SSD")}
            ${inputField("显卡", "gpu", computer.gpu, false, "集成显卡 / RTX 4060")}
          </div>
        </section>
        <section class="modal-section">
          <div class="form-grid three">
            ${inputField("固资编码", "fixedAssetCode", computer.fixedAssetCode, false, "FA-2026-0001")}
            ${inputField("SN / ST", "snSt", computer.snSt, false, "序列号")}
            ${inputField("位置", "location", computer.location, false, "总部 / IT")}
            ${inputField("购置日期", "purchaseDate", computer.purchaseDate, false, "", "date")}
            ${inputField("注册日期", "registeredDate", computer.registeredDate, false, "", "date")}
            ${inputField("Wifi MAC", "wifiMac", computer.wifiMac, false, "11-22-33-44-55-66")}
            ${inputField("网口 MAC", "ethernetMac", computer.ethernetMac, false, "11-22-33-44-55-66")}
            ${inputField("部门", "department", computer.department, false, "IT")}
          </div>
        </section>
        <section class="modal-section">
          <div class="form-grid">
            ${selectField(
              "使用用户",
              "userId",
              computer.userId || "",
              [{ value: "", label: "未分配" }].concat(
                sortEmployees(state.employees).map((employee) => ({
                  value: employee.id,
                  label: `${employee.name} · ${employee.employeeNo} · ${orgName(employee.orgId)}`,
                })),
              ),
              false,
            )}
            ${inputField("备注", "remarks", computer.remarks || "", false, "可填写采购批次、工单号等")}
          </div>
        </section>
        <div class="modal-footer"><button type="button" class="secondary-button" data-action="close-modal">取消</button><button class="primary-button" type="submit">保存电脑</button></div>
      </form>`,
  );
}

function openEmployeeModal(id = "", presetOrgId = "") {
  const employee = state.employees.find((item) => item.id === id) || {
    id: "",
    employeeNo: "",
    name: "",
    orgId: presetOrgId || state.orgs[0]?.id || "",
    department: "",
    position: "",
    email: "",
    mobile: "",
    status: "active",
    leaveDate: "",
    leaveInfo: "",
    leaveRemark: "",
  };
  const isEditing = Boolean(id);
  const hasExistingNumber = Boolean(String(employee.employeeNo || "").trim());
  const initialEmployeeNo = hasExistingNumber ? employee.employeeNo : employeeNumberFor(employee.orgId, employee.id);
  openModal(
    `${modalHeader(isEditing ? "编辑使用人员" : "新增使用人员", "人员归属到组织树节点后，会同步出现在树状视图中")}
      <form data-form="employee" data-id="${escapeHtml(employee.id)}">
        <section class="modal-section">
          <div class="form-grid">
            ${inputField(
              "人员编号",
              "employeeNo",
              initialEmployeeNo,
              true,
              "SZNS-ITQ-IT-001",
              "text",
              "",
              `data-employee-number data-original-number="${escapeHtml(employee.employeeNo || "")}" data-generated="${hasExistingNumber ? "false" : "true"}"`,
            )}
            ${inputField("人员姓名", "name", employee.name, true, "姓名")}
            ${selectField(
              "所属组织",
              "orgId",
              employee.orgId,
              getOrgSelectOptions({ includeBlank: true }),
              false,
            )}
            ${selectField(
              "人员状态",
              "status",
              employee.status,
              ["active", "inactive", "left"].map((value) => ({ value, label: statusLabels[value] })),
              true,
            )}
            ${inputField("部门", "department", employee.department, false, "IT")}
            ${inputField("岗位", "position", employee.position, false, "IT 管理员")}
            ${inputField("邮箱", "email", employee.email, false, "name@example.com", "email")}
            ${inputField("手机号", "mobile", employee.mobile, false, "138****0000")}
          </div>
        </section>
        <section class="modal-section" data-left-fields ${
          employee.status === "left" ? "" : 'hidden style="display:none;"'
        }>
          <div class="form-grid three">
            ${inputField(
              "离职日期",
              "leaveDate",
              employee.leaveDate || (employee.status === "left" ? currentDateText() : ""),
              false,
              "",
              "date",
            )}
          </div>
          <div class="form-grid">
            ${textareaField("离职信息", "leaveInfo", employee.leaveInfo || "", false, "如离职原因、交接情况等", 3)}
            ${textareaField("备注", "leaveRemark", employee.leaveRemark || "", false, "仅在标记离职时写入离职人员档案", 3)}
          </div>
        </section>
        <div class="modal-footer"><button type="button" class="secondary-button" data-action="close-modal">取消</button><button class="primary-button" type="submit">保存人员</button></div>
      </form>`,
  );
}

function leftEmployeeReadonlyField(label, value, type = "text") {
  return inputField(label, `readonly-${label}`, value, false, "", type, "", 'readonly tabindex="-1"');
}

function openLeftEmployeeModal(id = "") {
  const employee = getLeftEmployee(id);
  if (!employee) return;
  openModal(
    `${modalHeader(`${employee.name} · 离职人员档案`, `${employee.employeeNo} · 已归档信息可在此查看`)}
      <section class="modal-section">
        <div class="form-grid">
          ${leftEmployeeReadonlyField("人员编号", employee.employeeNo || "—")}
          ${leftEmployeeReadonlyField("人员姓名", employee.name || "—")}
          ${leftEmployeeReadonlyField("原组织路径", employee.orgPath || orgPathName(employee.orgId))}
          ${leftEmployeeReadonlyField("部门", employee.department || "—")}
          ${leftEmployeeReadonlyField("岗位", employee.position || "—")}
          ${leftEmployeeReadonlyField("离职日期", employee.leaveDate || "—")}
          ${leftEmployeeReadonlyField("归档时间", formatDateTime(employee.archivedAt || ""))}
          ${leftEmployeeReadonlyField("手机号", employee.mobile || "—")}
        </div>
      </section>
      <section class="modal-section">
        <div class="form-grid">
          ${textareaField("离职信息", "left-detail-info", employee.leaveInfo || "", false, "", 4, 'readonly tabindex="-1"')}
          ${textareaField("备注", "left-detail-remark", employee.leaveRemark || "", false, "", 4, 'readonly tabindex="-1"')}
        </div>
      </section>
      <section class="modal-section">
        <div class="modal-section-title"><div><h3>离职时设备快照</h3><span>${(employee.devices || []).length} 条</span></div></div>
        ${leftEmployeeDeviceChips(employee.devices || [])}
      </section>
      <div class="modal-footer"><button type="button" class="secondary-button" data-action="close-modal">关闭</button></div>`,
    true,
  );
}

function toggleEmployeeLeaveFields(form, shouldAutofill = false) {
  if (!form || form.dataset.form !== "employee") return;
  const status = form.elements.status?.value || "active";
  const leaveSection = form.querySelector("[data-left-fields]");
  if (!leaveSection) return;
  const isLeft = status === "left";
  leaveSection.hidden = !isLeft;
  leaveSection.style.display = isLeft ? "" : "none";
  const leaveDateInput = form.elements.leaveDate;
  if (isLeft && leaveDateInput && shouldAutofill && !String(leaveDateInput.value || "").trim()) {
    leaveDateInput.value = currentDateText();
  }
}

function inventoryBrandOptions(typeId, selectedId = "", currentName = "") {
  const brands = inventoryBrandsForType(typeId);
  const matched = brands.find((brand) => brand.id === selectedId || (currentName && brand.name === currentName));
  return [{ value: "__custom__", label: "自定义品牌" }].concat(
    brands.map((brand) => ({ value: brand.id, label: brand.name })),
  ).map((option) => ({
    ...option,
    selected: String(option.value) === String(matched?.id || "__custom__"),
  }));
}

function inventoryModelOptions(brandId, selectedId = "", currentName = "") {
  const models = inventoryModelsForBrand(brandId);
  const matched = models.find((model) => model.id === selectedId || (currentName && model.name === currentName));
  return [{ value: "__custom__", label: "自定义型号" }].concat(
    models.map((model) => ({ value: model.id, label: inventoryModelOptionLabel(model) })),
  ).map((option) => ({
    ...option,
    selected: String(option.value) === String(matched?.id || "__custom__"),
  }));
}

function inventorySelectField(label, name, options, required = false) {
  return `<div class="form-field"><label>${escapeHtml(label)}${required ? " *" : ""}</label><select name="${escapeHtml(
    name,
  )}" data-inventory-select="${escapeHtml(name)}" ${required ? "required" : ""}>${options
    .map(
      (option) =>
        `<option value="${escapeHtml(option.value)}" ${option.selected ? "selected" : ""}>${escapeHtml(
          option.label,
        )}</option>`,
    )
    .join("")}</select></div>`;
}

function renderInventorySelectionFields(item = {}, includeType = true) {
  const typeId = item.typeId || defaultMonitorTypeId();
  const selectedBrand = getInventoryBrand(item.inventoryBrandId) || inventoryBrandsForType(typeId).find(
    (brand) => brand.name === item.brand,
  );
  const selectedModel = getInventoryModel(item.inventoryModelId) || inventoryModelsForBrand(selectedBrand?.id || "").find(
    (model) => model.name === item.model,
  );
  const brandOptions = inventoryBrandOptions(typeId, selectedBrand?.id || "", item.brand || "");
  const modelOptions = inventoryModelOptions(selectedBrand?.id || "", selectedModel?.id || "", item.model || "");
  return `
    ${
      includeType
        ? selectField(
            "设备类型",
            "typeId",
            typeId,
            state.nonAssetTypes.map((type) => ({ value: type.id, label: type.name })),
            true,
          )
        : ""
    }
    ${inventorySelectField("库存品牌", "brandId", brandOptions, false)}
    ${inputField("品牌 / 自定义", "brandCustom", selectedBrand ? "" : item.brand || "", false, "自定义品牌")}
    ${inventorySelectField("库存型号", "modelId", modelOptions, false)}
    ${inputField("型号 / 自定义", "modelCustom", selectedModel ? "" : item.model || "", false, "自定义型号")}
  `;
}

function renderComputerInventorySelectionFields(computer = {}) {
  const typeId = computerInventoryTypeId();
  if (!typeId) {
    return `
      ${inputField("设备品牌", "brand", computer.brand, false, "Dell / Lenovo / HP")}
      ${inputField("型号", "model", computer.model, false, "Latitude 5440")}
    `;
  }
  const linkedModel = getInventoryModel(computer.inventoryModelId);
  const selectedBrand =
    (linkedModel && getInventoryBrand(linkedModel.brandId)) ||
    inventoryBrandsForType(typeId).find((brand) => brand.name === computer.brand);
  const selectedModel =
    linkedModel ||
    inventoryModelsForBrand(selectedBrand?.id || "").find((model) => model.name === computer.model);
  const selectedComputerBrand = selectedBrand?.name || computer.brand || "";
  const selectedComputerModel = selectedModel?.name || computer.model || "";
  const brandOptions = [{ value: "__custom__", label: "自定义品牌" }]
    .concat(inventoryBrandsForType(typeId).map((brand) => ({ value: brand.id, label: brand.name })))
    .map((option) => ({
      ...option,
      selected: String(option.value) === String(selectedBrand?.id || "__custom__"),
    }));
  const modelOptions = [{ value: "__custom__", label: "自定义型号" }]
    .concat(inventoryModelsForBrand(selectedBrand?.id || "").map((model) => ({ value: model.id, label: inventoryModelOptionLabel(model) })))
    .map((option) => ({
      ...option,
      selected: String(option.value) === String(selectedModel?.id || "__custom__"),
    }));
  return `
    ${inventorySelectField("库存电脑品牌", "computerInventoryBrandId", brandOptions, false)}
    ${inputField("设备品牌", "brand", selectedComputerBrand, false, "Dell / Lenovo / HP")}
    ${inventorySelectField("库存电脑型号", "computerInventoryModelId", modelOptions, false)}
    ${inputField("型号", "model", selectedComputerModel, false, "Latitude 5440")}
  `;
}

function updateComputerInventorySelectors(form, changedField) {
  if (!form || form.dataset.form !== "computer") return;
  const typeId = computerInventoryTypeId();
  const brandSelect = form.elements.computerInventoryBrandId;
  const modelSelect = form.elements.computerInventoryModelId;
  if (!typeId || !brandSelect || !modelSelect) return;

  if (changedField === "computerInventoryBrandId") {
    const brand = brandSelect.value && brandSelect.value !== "__custom__" ? getInventoryBrand(brandSelect.value) : null;
    replaceSelectOptions(
      modelSelect,
      [{ value: "__custom__", label: "自定义型号" }].concat(
        inventoryModelsForBrand(brand?.id || "").map((model) => ({
          value: model.id,
          label: inventoryModelOptionLabel(model),
        })),
      ),
    );
    if (brand && form.elements.brand) form.elements.brand.value = brand.name;
    if (form.elements.model) form.elements.model.value = "";
    ["cpu", "memory", "storage", "gpu"].forEach((fieldName) => {
      if (form.elements[fieldName]) form.elements[fieldName].value = "";
    });
    return;
  }

  if (changedField === "computerInventoryModelId") {
    const model = modelSelect.value && modelSelect.value !== "__custom__" ? getInventoryModel(modelSelect.value) : null;
    if (!model) return;
    const brand = getInventoryBrand(model.brandId);
    if (brandSelect && brand) brandSelect.value = brand.id;
    if (form.elements.brand && brand) form.elements.brand.value = brand.name;
    if (form.elements.model) form.elements.model.value = model.name || "";
    if (form.elements.cpu) form.elements.cpu.value = model.cpu || "";
    if (form.elements.memory) form.elements.memory.value = model.memory || "";
    if (form.elements.storage) form.elements.storage.value = normalizeStorageValue(model.storage || "");
    if (form.elements.gpu) form.elements.gpu.value = model.gpu || "";
    if (form.elements.purchaseDate && !form.elements.purchaseDate.value && model.inboundDate) {
      form.elements.purchaseDate.value = model.inboundDate;
    }
  }
}

function renderMonitorModule(employeeId, monitor = {}, isDraft = false) {
  const id = monitor.id || "";
  const summary = [monitor.brand, monitor.model].filter(Boolean).join(" ") || "新增显示屏";
  const removeAction = id ? "delete-monitor" : "remove-device-module";
  return `
    <form class="device-module monitor-module" data-form="monitor" data-employee-id="${escapeHtml(
      employeeId,
    )}" data-id="${escapeHtml(id)}" ${isDraft ? 'data-draft="true"' : ""}>
      <div class="device-module-header">
        <div><strong>${escapeHtml(summary)}</strong><small>可关联 IT 物资库存中的类型、品牌、型号，也可自定义填写。</small></div>
        <div class="device-module-header-actions">
          ${
            id
              ? `<label class="device-recover-select"><input type="checkbox" data-recovery-select data-recovery-kind="monitor" data-employee-id="${escapeHtml(
                  employeeId,
                )}" data-id="${escapeHtml(id)}" />回收</label>`
              : ""
          }
          <button type="button" class="text-button danger" data-action="${removeAction}" ${
            id ? `data-id="${escapeHtml(id)}" data-employee-id="${escapeHtml(employeeId)}"` : ""
          }>删除</button>
        </div>
      </div>
      <div class="device-module-grid">
        ${renderInventorySelectionFields({ ...monitor, typeId: monitor.typeId || defaultMonitorTypeId() }, true)}
      </div>
      <div class="device-module-actions"><button class="primary-button" type="submit">${
        id ? "保存修改" : "保存显示屏"
      }</button></div>
    </form>`;
}

function renderNonAssetModule(employeeId, item = {}, isDraft = false) {
  const id = item.id || "";
  const typeId = item.typeId || state.nonAssetTypes[0]?.id || "mouse";
  const type = getType(typeId);
  const summary = type?.name || "非资产设备";
  const removeAction = id ? "delete-nonasset" : "remove-device-module";
  return `
    <form class="device-module nonasset-module" data-form="nonasset" data-employee-id="${escapeHtml(
      employeeId,
    )}" data-id="${escapeHtml(id)}" ${isDraft ? 'data-draft="true"' : ""}>
      <div class="device-module-header">
        <div><strong>${escapeHtml(summary)}</strong><small>可关联 IT 物资库存中的类型、品牌、型号，也可自定义填写。</small></div>
        <div class="device-module-header-actions">
          ${
            id
              ? `<label class="device-recover-select"><input type="checkbox" data-recovery-select data-recovery-kind="nonasset" data-employee-id="${escapeHtml(
                  employeeId,
                )}" data-id="${escapeHtml(id)}" />回收</label>`
              : ""
          }
          <button type="button" class="text-button danger" data-action="${removeAction}" ${
            id ? `data-id="${escapeHtml(id)}" data-employee-id="${escapeHtml(employeeId)}"` : ""
          }>删除</button>
        </div>
      </div>
      <div class="device-module-grid">
        ${renderInventorySelectionFields({ ...item, typeId }, true)}
        ${inputField("Quantity", "quantity", Math.max(1, Number(item.quantity || 1)), true, "1", "number", "1")}
      </div>
      <div class="device-module-actions"><button class="primary-button" type="submit">${
        id ? "保存修改" : "保存非资产设备"
      }</button></div>
    </form>`;
}

function openDeviceManager(employeeId) {
  const employee = getEmployee(employeeId);
  if (!employee) return;
  const assignedComputers = state.computers.filter((computer) => computer.userId === employeeId);
  const availableComputers = state.computers.filter(
    (computer) => !computer.userId && !["retired", "lost"].includes(computer.status),
  );
  const monitors = employee.monitors || [];
  const nonAssetItems = getNonAssetItems(employee);
  const defaultNonAssetTypeId = state.nonAssetTypes.find((type) => type.id === "mouse")?.id || state.nonAssetTypes[0]?.id || "mouse";

  openModal(
    `${modalHeader(`${employee.name} · 设备清单`, `${employee.employeeNo} · ${orgPathName(employee.orgId)} · ${employee.department || "未填写部门"}`)}
      <section class="modal-section">
        <div class="modal-section-title"><h3>办公电脑</h3><span>${assignedComputers.length} 台</span></div>
        ${
          assignedComputers.length
            ? assignedComputers
                .map(
                  (computer) => `<div class="assignment-row">
                    <div><strong>${escapeHtml(computer.deviceName)}</strong><small>${escapeHtml(
                      [computer.brand, computer.model].filter(Boolean).join(" · ") || "未填写品牌型号",
                    )} · ${escapeHtml(computer.fixedAssetCode || "未登记固资编码")} · ${escapeHtml(
                      orgPathName(computer.orgId),
                    )}</small></div>
                    <div class="inline-actions"><button class="text-button" data-action="open-computer" data-id="${escapeHtml(
                      computer.id,
                    )}">编辑台账</button><button class="text-button danger" data-action="release-computer" data-id="${escapeHtml(
                      computer.id,
                    )}" data-employee-id="${escapeHtml(employee.id)}">解除</button></div>
                  </div>`,
                )
                .join("")
            : '<div class="empty-state">当前没有分配电脑</div>'
        }
        <div class="assignment-form">
          <select data-assign-computer="${escapeHtml(employee.id)}">
            <option value="">选择一台可分配电脑</option>
            ${availableComputers
              .map(
                (computer) =>
                  `<option value="${escapeHtml(computer.id)}">${escapeHtml(computer.deviceName)} · ${escapeHtml(
                    computer.model || "未填写型号",
                  )} · ${escapeHtml(orgName(computer.orgId))}</option>`,
              )
              .join("")}
          </select>
          <button class="primary-button" data-action="assign-computer" data-employee-id="${escapeHtml(
            employee.id,
          )}">分配</button>
        </div>
      </section>

      <section class="modal-section">
        <div class="modal-section-title">
          <div><h3>显示屏</h3><span>${monitors.length} 个模块，仅记录品牌和型号</span></div>
        </div>
        <div class="device-module-list" data-monitor-list="${escapeHtml(employee.id)}">
          ${
            monitors.length
              ? monitors.map((monitor) => renderMonitorModule(employee.id, monitor)).join("")
              : renderMonitorModule(employee.id, {}, true)
          }
        </div>
        <div class="module-list-footer">
          <button type="button" class="secondary-button" data-action="recover-selected-devices" data-kind="monitor" data-employee-id="${escapeHtml(
            employee.id,
          )}">回收选中</button>
          <button type="button" class="add-module-button" data-action="add-monitor-module" data-employee-id="${escapeHtml(
            employee.id,
          )}">＋ 添加显示屏</button>
        </div>
      </section>

      <section class="modal-section">
        <div class="modal-section-title">
          <div><h3>非资产设备</h3><span>默认显示 1 个鼠标模块，可按需继续添加</span></div>
        </div>
        <div class="device-module-list" data-nonasset-list="${escapeHtml(employee.id)}">
          ${
            nonAssetItems.length
              ? nonAssetItems.map((item) => renderNonAssetModule(employee.id, item)).join("")
              : renderNonAssetModule(employee.id, { typeId: defaultNonAssetTypeId, quantity: 1 }, true)
          }
        </div>
        <div class="module-list-footer">
          <button type="button" class="secondary-button" data-action="recover-selected-devices" data-kind="nonasset" data-employee-id="${escapeHtml(
            employee.id,
          )}">回收选中</button>
          <button type="button" class="add-module-button" data-action="add-nonasset-module" data-employee-id="${escapeHtml(
            employee.id,
          )}">＋ 添加非资产设备</button>
        </div>
      </section>`,
    true,
  );
}

function openOrgModal(id = "", presetParentId = "") {
  const existing = state.orgs.find((item) => item.id === id);
  const org = existing || { id: "", code: "", name: "", parentId: presetParentId, sortOrder: 1000 };
  const excludeIds = existing ? [existing.id].concat(getDescendantOrgIds(existing.id)) : [];
  openModal(
    `${modalHeader(id ? "编辑组织" : "新增组织", "组织会用于树状视图展示和电脑、人员归属")}
      <form data-form="org" data-id="${escapeHtml(org.id)}">
        <div class="form-grid">
          ${inputField(
            "组织编码",
            "code",
            org.code || orgCodeFor(org, org.parentId, org.id),
            true,
            "ITQ",
            "text",
            "",
            `data-org-code data-original-code="${escapeHtml(org.code || "")}" data-generated="${id ? "false" : "true"}"`,
          )}
          ${inputField("组织名称", "name", org.name, true, "人力资源部")}
          ${selectField(
            "上级组织",
            "parentId",
            org.parentId || "",
            getOrgSelectOptions({
              includeBlank: true,
              blankLabel: "作为根组织",
              excludeIds,
            }),
            false,
          )}
          ${inputField("排序值", "sortOrder", org.sortOrder || 1000, true, "10", "number", "0")}
        </div>
        <div class="modal-footer"><button type="button" class="secondary-button" data-action="close-modal">取消</button><button class="primary-button" type="submit">保存组织</button></div>
      </form>`,
  );
}

function openTypeModal(id = "") {
  const type = state.nonAssetTypes.find((item) => item.id === id) || { id: "", code: "", name: "", unit: "件" };
  openModal(
    `${modalHeader(id ? "编辑非资产设备类型" : "新增非资产设备类型", "用于人员设备清单中的数量统计")}
      <form data-form="type" data-id="${escapeHtml(type.id)}">
        <div class="form-grid">${inputField("类型编码", "code", type.code, true, "mouse")}${inputField(
          "类型名称",
          "name",
          type.name,
          true,
          "鼠标",
        )}${inputField("计量单位", "unit", type.unit, true, "件")}</div>
        <div class="modal-footer"><button type="button" class="secondary-button" data-action="close-modal">取消</button><button class="primary-button" type="submit">保存类型</button></div>
      </form>`,
  );
}

function inputField(
  label,
  name,
  value,
  required = false,
  placeholder = "",
  type = "text",
  min = "",
  extraAttributes = "",
) {
  return `<div class="form-field"><label>${escapeHtml(label)}${required ? " *" : ""}</label><input type="${type}" name="${escapeHtml(
    name,
  )}" value="${escapeHtml(value)}" placeholder="${escapeHtml(placeholder)}" ${required ? "required" : ""} ${
    min ? `min="${escapeHtml(min)}"` : ""
  } ${extraAttributes} /></div>`;
}

function selectField(label, name, value, options, required = false) {
  return `<div class="form-field"><label>${escapeHtml(label)}${required ? " *" : ""}</label><select name="${escapeHtml(
    name,
  )}" ${required ? "required" : ""}>${options
    .map(
      (option) =>
        `<option value="${escapeHtml(option.value)}" ${String(value) === String(option.value) ? "selected" : ""}>${escapeHtml(
          option.label,
        )}</option>`,
    )
    .join("")}</select></div>`;
}

function textareaField(label, name, value, required = false, placeholder = "", rows = 3, extraAttributes = "") {
  return `<div class="form-field"><label>${escapeHtml(label)}${required ? " *" : ""}</label><textarea name="${escapeHtml(
    name,
  )}" rows="${rows}" placeholder="${escapeHtml(placeholder)}" ${required ? "required" : ""} ${extraAttributes}>${escapeHtml(
    value,
  )}</textarea></div>`;
}

async function handleSystemSettingsSubmit(form) {
  if (!isAdminUser()) return showToast("只有管理员可以修改系统设置", true);
  const data = Object.fromEntries(new FormData(form).entries());
  try {
    const payload = await requestJson(API_SETTINGS_URL, {
      method: "PUT",
      body: JSON.stringify({
        settings: {
          app_name: data.app_name,
          login_notice: data.login_notice,
          session_hours: data.session_hours,
        },
      }),
    });
    settingsState.settings = payload.settings || settingsState.settings;
    updateAuthenticatedChrome();
    render();
    showToast("系统设置已保存");
  } catch (error) {
    showToast(`保存系统设置失败：${error.message}`, true);
  }
}

async function handleBackupScheduleSubmit(form) {
  if (!isAdminUser()) return showToast("只有管理员可以修改数据库备份设置", true);
  const enabled = form.querySelector('input[name="backup_enabled"]')?.checked;
  const data = Object.fromEntries(new FormData(form).entries());
  try {
    const payload = await requestJson(API_SETTINGS_URL, {
      method: "PUT",
      body: JSON.stringify({
        settings: {
          backup_enabled: enabled ? "1" : "0",
          backup_time: data.backup_time,
          backup_retention_days: data.backup_retention_days,
        },
      }),
    });
    settingsState.settings = payload.settings || settingsState.settings;
    render();
    showToast("数据库备份计划已保存");
  } catch (error) {
    showToast(`保存数据库备份计划失败：${error.message}`, true);
  }
}

async function handleUpdateCheck(button) {
  if (!isAdminUser()) return showToast("只有管理员可以检查并执行版本更新", true);
  settingsState.updateChecking = true;
  if (button) button.disabled = true;
  render();
  try {
    const payload = await requestJson(API_UPDATE_CHECK_URL, {
      method: "POST",
      body: "{}",
    });
    settingsState.updateStatus = payload;
    const status = payload.status || "";
    if (status === "up_to_date") {
      showToast(`当前已是最新版本 ${payload.currentShortSha || ""}`);
    } else if (status === "queued" || status === "running") {
      showToast(`发现新版本 ${payload.latestShortSha || ""}，更新已开始`);
      window.setTimeout(() => window.location.reload(), 7000);
    } else {
      showToast("版本检查已完成");
    }
  } catch (error) {
    showToast(`检查版本更新失败：${error.message}`, true);
  } finally {
    settingsState.updateChecking = false;
    render();
  }
}

async function handleDatabaseBackupCreate(button) {
  if (!isAdminUser()) return showToast("只有管理员可以创建数据库备份", true);
  if (button) button.disabled = true;
  try {
    const payload = await requestJson(API_BACKUPS_URL, {
      method: "POST",
      body: "{}",
    });
    settingsState.backups = Array.isArray(payload.backups) ? payload.backups : settingsState.backups;
    render();
    showToast(`数据库备份已创建：${payload.backup?.fileName || ""}`);
  } catch (error) {
    showToast(`创建数据库备份失败：${error.message}`, true);
  } finally {
    if (button?.isConnected) button.disabled = false;
  }
}

async function handleDatabaseBackupDownloadSubmit(form) {
  if (!isAdminUser()) return showToast("只有管理员可以下载数据库备份", true);
  const backupId = form.dataset.id || "";
  const data = Object.fromEntries(new FormData(form).entries());
  const submit = form.querySelector('button[type="submit"]');
  if (submit) submit.disabled = true;
  try {
    const filename = await requestDownload(`${API_BACKUPS_URL}/${encodeURIComponent(backupId)}/download`, {
      password: data.password || "",
    });
    closeModal();
    showToast(`已开始下载：${filename}`);
  } catch (error) {
    showToast(`下载数据库备份失败：${error.message}`, true);
  } finally {
    if (submit?.isConnected) submit.disabled = false;
  }
}

async function handleChangePasswordSubmit(form) {
  const data = Object.fromEntries(new FormData(form).entries());
  try {
    await requestJson(API_AUTH_CHANGE_PASSWORD_URL, {
      method: "POST",
      body: JSON.stringify(data),
    });
    form.reset();
    showToast("密码已修改");
  } catch (error) {
    showToast(`修改密码失败：${error.message}`, true);
  }
}

async function handleUserAccountSubmit(form) {
  if (!isAdminUser()) return showToast("只有管理员可以管理账号", true);
  const data = Object.fromEntries(new FormData(form).entries());
  const id = form.dataset.id || "";
  const payload = {
    username: String(data.username || "").trim(),
    displayName: String(data.displayName || "").trim(),
    role: data.role,
    isActive: data.isActive === "1",
  };
  if (String(data.password || "").trim()) payload.password = data.password;
  try {
    await requestJson(id ? `${API_USERS_URL}/${encodeURIComponent(id)}` : API_USERS_URL, {
      method: id ? "PUT" : "POST",
      body: JSON.stringify(payload),
    });
    const usersPayload = await requestJson(API_USERS_URL);
    settingsState.users = Array.isArray(usersPayload.users) ? usersPayload.users : [];
    closeModal();
    render();
    showToast(id ? "账号已更新" : "账号已创建");
  } catch (error) {
    showToast(`保存账号失败：${error.message}`, true);
  }
}

function handleComputerSubmit(form) {
  const data = Object.fromEntries(new FormData(form).entries());
  const id = form.dataset.id;
  const previous = state.computers.find((computer) => computer.id === id);
  const duplicate = state.computers.find((computer) => computer.deviceName === data.deviceName && computer.id !== id);
  if (duplicate) return showToast("设备名已经存在", true);
  const selectedInventoryModel =
    data.computerInventoryModelId && data.computerInventoryModelId !== "__custom__"
      ? getInventoryModel(data.computerInventoryModelId)
      : null;
  const selectedInventoryBrand = selectedInventoryModel ? getInventoryBrand(selectedInventoryModel.brandId) : null;
  if (!id && selectedInventoryModel && Number(selectedInventoryModel.quantity || 0) < 1) {
    return showToast(`库存型号 ${selectedInventoryModel.name} 当前没有可用库存。`, true);
  }
  const wifiMac = normalizeMacAddress(data.wifiMac);
  const ethernetMac = normalizeMacAddress(data.ethernetMac);
  if (!isValidMacAddress(wifiMac)) {
    return showToast("Wifi MAC 格式不正确，请输入 11-22-33-44-55-66 或 11:22:33:44:55:66", true);
  }
  if (!isValidMacAddress(ethernetMac)) {
    return showToast("网口 MAC 格式不正确，请输入 11-22-33-44-55-66 或 11:22:33:44:55:66", true);
  }

  const computer = normalizeComputerRecord({
    id: id || createId("pc"),
    deviceName: data.deviceName,
    orgId: data.orgId,
    deviceType: data.deviceType,
    brand: selectedInventoryBrand?.name || data.brand,
    model: selectedInventoryModel?.name || data.model,
    inventoryModelId: selectedInventoryModel?.id || "",
    cpu: selectedInventoryModel?.cpu || data.cpu,
    memory: selectedInventoryModel?.memory || data.memory,
    storage: normalizeStorageValue(selectedInventoryModel?.storage || data.storage),
    gpu: selectedInventoryModel?.gpu || data.gpu,
    fixedAssetCode: data.fixedAssetCode,
    purchaseDate: data.purchaseDate || selectedInventoryModel?.inboundDate || "",
    registeredDate: data.registeredDate,
    snSt: data.snSt,
    wifiMac,
    ethernetMac,
    location: data.location,
    department: data.department,
    status: data.status,
    userId: ["repair", "retired", "lost"].includes(data.status) ? null : data.userId || null,
    inventoryStockAdjusted: Boolean(
      selectedInventoryModel &&
        (!previous || previous.inventoryStockAdjusted || previous.inventoryModelId !== selectedInventoryModel.id),
    ),
    remarks: data.remarks,
  });

  const movements = new Map();
  const addMovement = (modelId, delta) => {
    if (!modelId || !delta) return;
    movements.set(modelId, (movements.get(modelId) || 0) + delta);
  };
  if (previous?.inventoryStockAdjusted && previous.inventoryModelId !== computer.inventoryModelId) {
    addMovement(previous.inventoryModelId, 1);
  }
  if (computer.inventoryStockAdjusted && previous?.inventoryModelId !== computer.inventoryModelId) {
    addMovement(computer.inventoryModelId, -1);
  }
  const stockMovements = [...movements.entries()].map(([modelId, delta]) => ({ modelId, delta }));
  if (stockMovements.length) {
    applyStockMovement(stockMovements);
    stockMovements.forEach(({ modelId, delta }) => {
      const model = getInventoryModel(modelId);
      const brand = model ? getInventoryBrand(model.brandId) : null;
      const type = model ? getType(model.typeId) : null;
      recordInventoryMovement({
        direction: delta < 0 ? "decrease" : "increase",
        typeName: type?.name || "电脑",
        brandName: brand?.name || "",
        modelName: model?.name || "",
        quantity: Math.abs(delta),
        sourceLabel: delta < 0 ? "IT物资库存" : `${previous?.deviceName || computer.deviceName}（办公电脑）`,
        targetLabel: delta < 0 ? `${computer.deviceName}（办公电脑）` : "IT物资库存",
        note: delta < 0 ? "新增或更换办公电脑时自动扣减库存" : "更换办公电脑库存型号时归还原库存",
        triggerAction: "computer_inventory_adjustment",
      });
    });
  }

  const index = state.computers.findIndex((item) => item.id === id);
  if (index >= 0) state.computers[index] = computer;
  else state.computers.unshift(computer);

  normalizeComputersAgainstEmployees();
  persistState(true);
  closeModal();
  render();
  showToast(id ? "电脑信息已更新" : "电脑已新增");
}

function handleEmployeeSubmit(form) {
  const data = Object.fromEntries(new FormData(form).entries());
  const id = form.dataset.id;
  const employeeNo = String(data.employeeNo || "").trim() || employeeNumberFor(data.orgId, id);
  const duplicate = state.employees.find((employee) => employee.employeeNo === employeeNo && employee.id !== id);
  if (duplicate) return showToast("人员编号已存在", true);

  const previous = state.employees.find((employee) => employee.id === id);
  if (data.status === "left") {
    const archiveEmployeeRecord = {
      ...previous,
      id: previous?.id || id || createId("emp"),
      employeeNo,
      name: data.name,
      orgId: data.orgId,
      department: data.department,
      position: data.position,
      email: data.email,
      mobile: data.mobile,
      status: "left",
      monitors: previous?.monitors || [],
      nonAssetItems: previous ? getNonAssetItems(previous) : [],
      nonAssets: {},
    };
    syncNonAssetAggregate(archiveEmployeeRecord);
    openLeaveRecoveryModal(archiveEmployeeRecord, {
      leaveDate: data.leaveDate || currentDateText(),
      leaveInfo: data.leaveInfo || "",
      leaveRemark: data.leaveRemark || "",
      archivedAt: currentTimestampText(),
    });
    return;
  }

  const employee = {
    ...previous,
    id: id || createId("emp"),
    employeeNo,
    name: data.name,
    orgId: data.orgId,
    department: data.department,
    position: data.position,
    email: data.email,
    mobile: data.mobile,
    status: data.status,
    monitors: previous?.monitors || [],
    nonAssetItems: previous
      ? getNonAssetItems(previous)
      : [
          {
            id: createId("na"),
            typeId: state.nonAssetTypes.find((type) => type.id === "mouse")?.id || state.nonAssetTypes[0]?.id || "mouse",
            brand: "",
            model: "",
            quantity: 1,
            inventoryBrandId: "",
            inventoryModelId: "",
            stockAdjusted: false,
          },
        ],
    nonAssets: {},
  };
  syncNonAssetAggregate(employee);

  const index = state.employees.findIndex((item) => item.id === id);
  if (index >= 0) state.employees[index] = employee;
  else state.employees.unshift(employee);

  ensureOrgExpanded(employee.orgId);
  normalizeComputersAgainstEmployees();
  persistState(true);
  closeModal();
  render();
  showToast(id ? "人员信息已更新" : "人员已新增");
}

function inventoryModelForItem(item) {
  if (item.inventoryModelId) {
    const selected = getInventoryModel(item.inventoryModelId);
    if (selected && selected.typeId === item.typeId) return selected;
  }
  const brand = state.inventoryBrands.find(
    (candidate) => candidate.typeId === item.typeId && candidate.name === item.brand,
  );
  return brand ? inventoryModelsForBrand(brand.id).find((model) => model.name === item.model) : null;
}

function stockMovementForDevice(previous, next, mode) {
  if (mode !== "deduct") return [];
  const movements = new Map();
  const addMovement = (model, delta) => {
    if (!model || !delta) return;
    movements.set(model.id, (movements.get(model.id) || 0) + delta);
  };
  if (previous?.stockAdjusted) {
    addMovement(inventoryModelForItem(previous), Math.max(1, Number(previous.quantity || 1)));
  }
  const nextModel = inventoryModelForItem(next);
  if (!nextModel) {
    throw new Error("所选品牌或型号不在 IT 物资库存中，请先在库存模块新增，或选择仅登记。");
  }
  addMovement(nextModel, -Math.max(1, Number(next.quantity || 1)));
  return [...movements.entries()].map(([modelId, delta]) => ({ modelId, delta }));
}

function applyStockMovement(movements) {
  const models = movements.map((movement) => ({
    movement,
    model: getInventoryModel(movement.modelId),
  }));
  const invalid = models.find(({ model }) => !model);
  if (invalid) {
    throw new Error("所选品牌或型号不在 IT 物资库存中，请先在库存模块新增，或选择仅登记。");
  }
  const insufficient = models.find(
    ({ movement, model }) => Number(model.quantity || 0) + movement.delta < 0,
  );
  if (insufficient) {
    throw new Error(`${insufficient.model.name} 库存不足，当前可用 ${insufficient.model.quantity}。`);
  }
  models.forEach(({ movement, model }) => {
    model.quantity = Math.max(0, Number(model.quantity || 0) + movement.delta);
  });
}

function openDeviceStockConfirm(kind, employeeId, item, previous) {
  pendingDeviceSave = { kind, employeeId, item, previous };
  const detail = [item.brand, item.model].filter(Boolean).join(" ") || "自定义物资";
  const quantity = Math.max(1, Number(item.quantity || 1));
  openModal(
    `${modalHeader("是否同步修改 IT 物资库存", `${detail} x${quantity}`)}
      <div class="confirm-panel">
        <p>请选择本次人员物资分配是否同步影响库存数量。</p>
        <div class="confirm-options">
          <button class="primary-button" data-action="commit-device-stock">同步扣减库存</button>
          <button class="secondary-button" data-action="commit-device-register">仅登记不扣减</button>
          <button class="secondary-button" data-action="cancel-device-confirm">取消</button>
        </div>
      </div>`,
    false,
  );
}

function finishDeviceSave(mode) {
  const pending = pendingDeviceSave;
  pendingDeviceSave = null;
  if (!pending) return;
  const employee = getEmployee(pending.employeeId);
  if (!employee) return;
  try {
    const movements = stockMovementForDevice(pending.previous, pending.item, mode);
    if (mode === "deduct") {
      applyStockMovement(movements);
      movements.forEach(({ modelId, delta }) => {
        if (!delta) return;
        const model = getInventoryModel(modelId);
        const names = modelLogNames(model);
        recordInventoryMovement({
          direction: delta < 0 ? "decrease" : "increase",
          ...names,
          quantity: Math.abs(delta),
          sourceLabel: delta < 0 ? "IT物资库存" : employeeLogLabel(employee.employeeNo, employee.name),
          targetLabel: delta < 0 ? employeeLogLabel(employee.employeeNo, employee.name) : "IT物资库存",
          note: pending.kind === "monitor" ? "显示屏领用同步库存" : "非资产设备领用同步库存",
          relatedEmployeeNo: employee.employeeNo || "",
          relatedEmployeeName: employee.name || "",
          triggerAction: delta < 0 ? "assignment" : "return_adjustment",
        });
      });
    }
  } catch (error) {
    showToast(error.message, true);
    openDeviceStockConfirm(pending.kind, pending.employeeId, pending.item, pending.previous);
    return;
  }

  const item = {
    ...pending.item,
    stockAdjusted: Boolean(pending.previous?.stockAdjusted || mode === "deduct"),
  };
  if (pending.kind === "monitor") {
    employee.monitors = employee.monitors || [];
    const index = employee.monitors.findIndex((existing) => existing.id === item.id);
    if (index >= 0) employee.monitors[index] = item;
    else employee.monitors.push(item);
  } else {
    employee.nonAssetItems = getNonAssetItems(employee);
    const index = employee.nonAssetItems.findIndex((existing) => existing.id === item.id);
    if (index >= 0) employee.nonAssetItems[index] = item;
    else employee.nonAssetItems.push(item);
    syncNonAssetAggregate(employee);
  }
  persistState(true);
  closeModal();
  openDeviceManager(employee.id);
  render();
  showToast(mode === "deduct" ? "已保存，并同步更新库存" : "已保存，库存未变更");
}

function handleMonitorSubmit(form) {
  const employee = getEmployee(form.dataset.employeeId);
  if (!employee) return;
  const data = Object.fromEntries(new FormData(form).entries());
  const resolved = resolveInventorySelection(data);
  if (!resolved.typeId || !resolved.brand || !resolved.model) {
    return showToast("请填写设备类型、品牌和型号。", true);
  }
  const previous = (employee.monitors || []).find((monitor) => monitor.id === form.dataset.id);
  const item = {
    id: form.dataset.id || createId("mon"),
    ...resolved,
    quantity: 1,
    stockAdjusted: Boolean(previous?.stockAdjusted),
  };
  openDeviceStockConfirm("monitor", employee.id, item, previous);
}

function handleNonAssetSubmit(form) {
  const employee = getEmployee(form.dataset.employeeId);
  if (!employee) return;
  const data = Object.fromEntries(new FormData(form).entries());
  const quantity = Math.max(1, Number(data.quantity || 0));
  const resolved = resolveInventorySelection(data);
  if (!resolved.typeId || !resolved.brand || !resolved.model || !quantity) {
    return showToast("请填写设备类型、品牌、型号和数量。", true);
  }
  const previous = getNonAssetItems(employee).find((item) => item.id === form.dataset.id);
  const item = {
    id: form.dataset.id || createId("na"),
    ...resolved,
    quantity,
    stockAdjusted: Boolean(previous?.stockAdjusted),
  };
  openDeviceStockConfirm("nonasset", employee.id, item, previous);
}

function handleOrgSubmit(form) {
  const data = Object.fromEntries(new FormData(form).entries());
  const orgId = form.dataset.id;
  const code = String(data.code || "").trim() || orgCodeFor({ name: data.name }, data.parentId, orgId);
  const duplicate = state.orgs.find(
    (org) => org.code.toUpperCase() === code.toUpperCase() && org.id !== orgId && (org.parentId || "") === (data.parentId || ""),
  );
  if (duplicate) return showToast("组织编码已经存在", true);

  if (orgId && data.parentId === orgId) {
    return showToast("上级组织不能选择当前组织", true);
  }

  if (orgId && data.parentId && getDescendantOrgIds(orgId).includes(data.parentId)) {
    return showToast("上级组织不能选择当前组织的下级节点", true);
  }

  const item = {
    id: orgId || createId("org"),
    code,
    name: data.name,
    parentId: data.parentId || "",
    sortOrder: Math.max(0, Number(data.sortOrder || 1000)),
  };

  const index = state.orgs.findIndex((org) => org.id === orgId);
  if (index >= 0) state.orgs[index] = item;
  else state.orgs.push(item);

  ensureOrgExpanded(item.parentId);
  ensureOrgExpanded(item.id);
  persistState(true);
  closeModal();
  render();
  showToast(index >= 0 ? "组织已更新" : "组织已新增");
}

function handleTypeSubmit(form) {
  const data = Object.fromEntries(new FormData(form).entries());
  const duplicate = state.nonAssetTypes.find((type) => type.code === data.code && type.id !== form.dataset.id);
  if (duplicate) return showToast("类型编码已经存在", true);

  const item = {
    id: form.dataset.id || createId("type"),
    code: data.code,
    name: data.name,
    unit: data.unit || "件",
  };

  const index = state.nonAssetTypes.findIndex((type) => type.id === form.dataset.id);
  if (index >= 0) state.nonAssetTypes[index] = item;
  else state.nonAssetTypes.push(item);

  ensureInventoryExpanded(item.id);
  persistState(true);
  closeModal();
  render();
  showToast(index >= 0 ? "设备类型已更新" : "设备类型已新增");
}

function handleInventoryBrandSubmit(form) {
  const data = Object.fromEntries(new FormData(form).entries());
  const typeId = form.dataset.typeId;
  const id = form.dataset.id;
  const name = String(data.name || "").trim();
  if (!typeId || !name) return showToast("请填写品牌名称。", true);
  const duplicate = state.inventoryBrands.find(
    (brand) => brand.typeId === typeId && brand.name.toLowerCase() === name.toLowerCase() && brand.id !== id,
  );
  if (duplicate) return showToast("该设备类型下已存在同名品牌。", true);

  const previous = getInventoryBrand(id);
  const item = {
    id: id || createId("brand"),
    typeId,
    name,
    sortOrder: Math.max(0, Number(data.sortOrder || 1000)),
  };
  const index = state.inventoryBrands.findIndex((brand) => brand.id === id);
  if (index >= 0) state.inventoryBrands[index] = item;
  else state.inventoryBrands.push(item);

  // Inventory brand records act as stock catalogs only.
  // Assigned devices keep their own brand snapshot and should not be rewritten here.
  ensureInventoryExpanded(typeId, item.id);
  persistState(true);
  closeModal();
  render();
  showToast(index >= 0 ? "库存品牌已更新" : "库存品牌已新增");
}

function handleInventoryModelSubmit(form) {
  const data = Object.fromEntries(new FormData(form).entries());
  const typeId = form.dataset.typeId;
  const brandId = form.dataset.brandId;
  const id = form.dataset.id;
  const name = String(data.name || "").trim();
  if (!typeId || !brandId || !name) return showToast("请填写型号名称。", true);
  const previous = getInventoryModel(id);
  const isComputerModel = isComputerInventoryType(getType(typeId));
  const batchKey = previous?.batchKey || (isComputerModel ? createId("batch") : "");
  const inboundDate = isComputerModel ? String(data.inboundDate || previous?.inboundDate || "").trim() : "";
  if (isComputerModel && !/^\d{4}-\d{2}-\d{2}$/.test(inboundDate)) {
    return showToast("电脑库存型号必须填写有效的入库时间。", true);
  }
  const duplicate = state.inventoryModels.find(
    (model) =>
      model.brandId === brandId &&
      model.name.toLowerCase() === name.toLowerCase() &&
      (model.batchKey || "") === batchKey &&
      model.id !== id,
  );
  if (duplicate) return showToast("该品牌下已存在同名型号。", true);

  const item = {
    id: id || createId("model"),
    typeId,
    brandId,
    name,
    batchKey,
    quantity: Math.max(0, Number(data.quantity || 0)),
    inboundDate,
    cpu: isComputerModel ? data.cpu || "" : "",
    memory: isComputerModel ? data.memory || "" : "",
    storage: isComputerModel ? normalizeStorageValue(data.storage) : "",
    gpu: isComputerModel ? data.gpu || "" : "",
    sortOrder: Math.max(0, Number(data.sortOrder || 1000)),
  };
  const index = state.inventoryModels.findIndex((model) => model.id === id);
  if (index >= 0) state.inventoryModels[index] = item;
  else state.inventoryModels.push(item);

  // Inventory model records act as stock catalogs only.
  // Assigned devices keep their own model snapshot and should not be rewritten here.
  const oldQuantity = Math.max(0, Number(previous?.quantity || 0));
  const newQuantity = Math.max(0, Number(item.quantity || 0));
  if (!previous && newQuantity > 0) {
    recordInventoryMovement({
      direction: "increase",
      typeName: getType(typeId)?.name || "",
      brandName: getInventoryBrand(brandId)?.name || "",
      modelName: item.name,
      quantity: newQuantity,
      sourceLabel: "手工新增",
      targetLabel: "IT物资库存",
      triggerAction: "manual_create",
    });
    state.inventoryPurchaseLogs.unshift({
      id: createId("purchase"),
      typeId,
      brandId,
      modelId: item.id,
      typeName: getType(typeId)?.name || "",
      brandName: getInventoryBrand(brandId)?.name || "",
      modelName: item.name,
      quantity: newQuantity,
      inboundDate: currentDateText(),
      cpu: isComputerModel ? item.cpu : "",
      memory: isComputerModel ? item.memory : "",
      storage: isComputerModel ? item.storage : "",
      gpu: isComputerModel ? item.gpu : "",
      sourceLabel: "手工新增",
      note: "通过库存型号页面手工新增库存",
      sourceMovementLogId: "",
      createdAt: currentTimestampText(),
    });
  } else if (previous && oldQuantity !== newQuantity) {
    recordInventoryMovement({
      direction: newQuantity > oldQuantity ? "increase" : "decrease",
      typeName: getType(typeId)?.name || "",
      brandName: getInventoryBrand(brandId)?.name || "",
      modelName: item.name,
      quantity: Math.abs(newQuantity - oldQuantity),
      sourceLabel: newQuantity > oldQuantity ? "手工调整" : "IT物资库存",
      targetLabel: newQuantity > oldQuantity ? "IT物资库存" : "手工调整",
      triggerAction: "manual_adjustment",
    });
  }
  ensureInventoryExpanded(typeId, brandId);
  persistState(true);
  closeModal();
  render();
  showToast(index >= 0 ? "库存型号已更新" : "库存型号已新增");
}

function handleInventoryImportSubmit(form) {
  const data = Object.fromEntries(new FormData(form).entries());
  const typeName = String(data.type || "").trim();
  const brandName = String(data.brand || "").trim();
  const modelName = String(data.model || "").trim();
  const quantity = Math.max(1, Number(data.quantity || 0));
  if (!typeName || !brandName || !modelName || !quantity) {
    return showToast("请填写类型、品牌、型号和数量。", true);
  }

  const isComputerImport = isComputerInventoryTypeName(typeName);
  const inboundDate = String(data.inboundDate || currentDateText()).trim();
  let type = isComputerImport ? computerInventoryType() || findInventoryTypeByName(typeName) : findInventoryTypeByName(typeName);
  if (!type) {
    type = {
      id: createId("type"),
      code: isComputerImport ? "computer" : inventoryTypeCodeFor(typeName),
      name: isComputerImport ? "电脑" : typeName,
      unit: isComputerImport ? "台" : "件",
      sortOrder: nextTypeSortOrder(),
    };
    state.nonAssetTypes.push(type);
  } else if (isComputerImport) {
    type.name = "电脑";
    type.code = type.code || "computer";
    type.unit = "台";
  }

  let brand = findInventoryBrandByName(type.id, brandName);
  if (!brand) {
    brand = {
      id: createId("brand"),
      typeId: type.id,
      name: brandName,
      sortOrder: nextBrandSortOrder(type.id),
    };
    state.inventoryBrands.push(brand);
  }

  let model = isComputerImport ? null : findInventoryModelByName(brand.id, modelName);
  if (!model) {
    model = {
      id: createId("model"),
      typeId: type.id,
      brandId: brand.id,
      name: modelName,
      batchKey: isComputerImport ? createId("batch") : "",
      quantity: 0,
      inboundDate: isComputerImport ? inboundDate : "",
      cpu: isComputerImport ? String(data.cpu || "").trim() : "",
      memory: isComputerImport ? String(data.memory || "").trim() : "",
      storage: isComputerImport ? normalizeStorageValue(data.storage) : "",
      gpu: isComputerImport ? String(data.gpu || "").trim() : "",
      sortOrder: nextModelSortOrder(brand.id),
    };
    state.inventoryModels.push(model);
  } else {
    model.batchKey = model.batchKey || "";
    if (isComputerImport) {
      model.inboundDate = model.inboundDate || inboundDate;
      model.cpu = model.cpu || String(data.cpu || "").trim();
      model.memory = model.memory || String(data.memory || "").trim();
      model.storage = model.storage || normalizeStorageValue(data.storage);
      model.gpu = model.gpu || String(data.gpu || "").trim();
    } else {
      model.inboundDate = "";
      model.cpu = "";
      model.memory = "";
      model.storage = "";
      model.gpu = "";
    }
  }
  model.quantity = Math.max(0, Number(model.quantity || 0)) + quantity;
  const configNote = inventoryModelConfigSummary(model);
  const noteParts = [
    String(data.note || "").trim(),
    isComputerImport && configNote ? `配置：${configNote}` : "",
  ].filter(Boolean);
  const movement = recordInventoryMovement({
    direction: "increase",
    typeName: type.name,
    brandName: brand.name,
    modelName: model.name,
    quantity,
    sourceLabel: isComputerImport ? "电脑入库" : "外部导入",
    targetLabel: "IT物资库存",
    note: noteParts.join("；"),
    triggerAction: "import",
  });
  state.inventoryPurchaseLogs.unshift({
    id: createId("purchase"),
    typeId: type.id,
    brandId: brand.id,
    modelId: model.id,
    typeName: type.name,
    brandName: brand.name,
    modelName: model.name,
    quantity,
    inboundDate,
    cpu: isComputerImport ? model.cpu : "",
    memory: isComputerImport ? model.memory : "",
    storage: isComputerImport ? model.storage : "",
    gpu: isComputerImport ? model.gpu : "",
    sourceLabel: isComputerImport ? "电脑入库" : "外部导入",
    note: String(data.note || "").trim(),
    sourceMovementLogId: movement.id,
    createdAt: currentTimestampText(),
  });

  state.filters.inventoryType = type.id;
  state.filters.inventoryBrand = brand.id;
  ensureInventoryExpanded(type.id, brand.id);
  persistState(true);
  closeModal();
  render();
  showToast(`已导入 ${type.name} / ${brand.name} / ${model.name}，数量 +${quantity}`);
}

function assignComputer(employeeId) {
  const select = document.querySelector(`[data-assign-computer="${CSS.escape(employeeId)}"]`);
  const computer = state.computers.find((item) => item.id === select?.value);
  if (!computer) return showToast("请选择可分配的电脑", true);

  computer.userId = employeeId;
  normalizeComputersAgainstEmployees();
  persistState(true);
  openDeviceManager(employeeId);
  render();
  showToast("电脑已分配");
}

function releaseComputer(computerId, employeeId) {
  const computer = state.computers.find((item) => item.id === computerId);
  if (!computer) return;

  computer.userId = null;
  computer.status = "idle";

  normalizeComputersAgainstEmployees();
  persistState(true);
  openDeviceManager(employeeId);
  render();
  showToast("电脑已解除分配");
}

function xmlEscape(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&apos;");
}

function safeSheetName(name) {
  return String(name || "Sheet1")
    .replace(/[\[\]\*\?\/\\:]/g, "")
    .slice(0, 31) || "Sheet1";
}

function excelCell(value, type = "String", styleId = "") {
  const style = styleId ? ` ss:StyleID="${styleId}"` : "";
  if (value === null || value === undefined || value === "") {
    return `<Cell${style}/>`;
  }
  return `<Cell${style}><Data ss:Type="${type}">${xmlEscape(value)}</Data></Cell>`;
}

function excelSheet(sheet) {
  const columns = sheet.headers
    .map((header) => `<Column ss:AutoFitWidth="0" ss:Width="${Math.min(260, Math.max(90, String(header).length * 10 + 28))}"/>`)
    .join("");
  const headerRow = `<Row>${sheet.headers.map((header) => excelCell(header, "String", "Header")).join("")}</Row>`;
  const rows = sheet.rows
    .map((row) => `<Row>${row.map((cell) => excelCell(cell.value ?? cell, cell.type || "String", cell.style || "")).join("")}</Row>`)
    .join("");

  return `<Worksheet ss:Name="${xmlEscape(safeSheetName(sheet.name))}"><Table>${columns}${headerRow}${rows}</Table></Worksheet>`;
}

function createExcelWorkbook(sheets) {
  return `<?xml version="1.0" encoding="UTF-8"?>
<?mso-application progid="Excel.Sheet"?>
<Workbook xmlns="urn:schemas-microsoft-com:office:spreadsheet"
  xmlns:o="urn:schemas-microsoft-com:office:office"
  xmlns:x="urn:schemas-microsoft-com:office:excel"
  xmlns:ss="urn:schemas-microsoft-com:office:spreadsheet"
  xmlns:html="http://www.w3.org/TR/REC-html40">
  <DocumentProperties xmlns="urn:schemas-microsoft-com:office:office">
    <Author>办公资产中台</Author>
    <Created>${new Date().toISOString()}</Created>
  </DocumentProperties>
  <Styles>
    <Style ss:ID="Default" ss:Name="Normal">
      <Alignment ss:Vertical="Center"/>
      <Font ss:FontName="Microsoft YaHei" ss:Size="10"/>
    </Style>
    <Style ss:ID="Header">
      <Font ss:FontName="Microsoft YaHei" ss:Size="10" ss:Bold="1" ss:Color="#FFFFFF"/>
      <Interior ss:Color="#17324D" ss:Pattern="Solid"/>
      <Alignment ss:Vertical="Center"/>
    </Style>
  </Styles>
  ${sheets.map(excelSheet).join("")}
</Workbook>`;
}

function downloadExcel(filename, sheets) {
  if (!sheets.length) return;
  const blob = new Blob([`\ufeff${createExcelWorkbook(sheets)}`], {
    type: "application/vnd.ms-excel;charset=utf-8",
  });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function exportDateStamp() {
  return new Date().toISOString().slice(0, 10).replaceAll("-", "");
}

function employeeDeviceExportSummary(employee) {
  const devices = employeeDevices(employee);
  const computerNames = devices
    .filter((device) => device.category === "computer")
    .map((device) => device.label);
  const monitorDetails = devices
    .filter((device) => device.category === "monitor")
    .map((device) => device.detail || device.label);
  const accessoryDetails = devices
    .filter((device) => device.category === "non-asset")
    .map((device) => `${device.label}${device.detail ? ` ${device.detail}` : ""}`);

  return {
    computers: computerNames.join("、"),
    monitors: monitorDetails.join("、"),
    accessories: accessoryDetails.join("、"),
  };
}

function employeeExportRows(employees) {
  return employees.map((employee) => {
    const deviceSummary = employeeDeviceExportSummary(employee);
    return [
      employee.employeeNo,
      employee.name,
      orgName(employee.orgId),
      orgPathName(employee.orgId),
      employee.department || "",
      employee.position || "",
      statusLabels[employee.status] || employee.status,
      deviceSummary.computers,
      deviceSummary.monitors,
      deviceSummary.accessories,
      employee.email || "",
      employee.mobile || "",
    ];
  });
}

function employeeDeviceExportRows(employees) {
  return employees.flatMap((employee) =>
    employeeDevices(employee).map((device) => [
      employee.employeeNo,
      employee.name,
      orgPathName(employee.orgId),
      device.category === "computer" ? "办公电脑" : device.category === "monitor" ? "显示屏" : "非资产设备",
      device.label,
      device.detail,
      device.quantity || 1,
    ]),
  );
}

function computerExportRows(computers) {
  return computers.map((computer) => {
    const user = getCurrentUser(computer);
    return [
      computer.deviceName,
      orgName(computer.orgId),
      orgPathName(computer.orgId),
      deviceTypeLabel(computer.deviceType),
      computer.brand || "",
      computer.model || "",
      computer.cpu || "",
      computer.memory || "",
      computer.storage || "",
      computer.gpu || "",
      computer.fixedAssetCode || "",
      computer.purchaseDate || "",
      computer.registeredDate || "",
      computer.snSt || "",
      computer.wifiMac || "",
      computer.ethernetMac || "",
      computer.location || "",
      computer.department || "",
      user?.name || "",
      statusLabels[computer.status] || computer.status,
    ];
  });
}

function inventoryDetailExportRows(rows) {
  return rows.map(({ type, brand, model }) => {
    return [
      type.name,
      brand.name,
      model.name,
      Math.max(0, Number(model.quantity || 0)),
      type.unit || "件",
    ];
  });
}

function inventoryMovementLogExportRows(logs) {
  return logs.map((log) => [
    formatDateTime(log.occurredAt),
    inventoryDirectionLabel(log.direction),
    log.typeName || "",
    log.brandName || "",
    log.modelName || "",
    log.quantity,
    log.sourceLabel || "",
    log.targetLabel || "",
    log.relatedEmployeeNo || "",
    log.relatedEmployeeName || "",
    log.triggerAction || "",
    log.note || "",
  ]);
}

function exportInventory() {
  const rows = inventoryFlatRows();
  if (!rows.length) return showToast("当前筛选条件下没有可导出的IT物资", true);

  downloadExcel(`办公资产-IT物资-${exportDateStamp()}.xls`, [
    {
      name: "IT物资明细",
      headers: ["设备类型", "品牌", "型号", "数量", "单位"],
      rows: inventoryDetailExportRows(rows),
    },
  ]);
  showToast(`已导出 ${rows.length} 条 IT 物资明细`);
}

function exportInventoryMovementLogsLegacy() {
  const logs = state.inventoryMovementLogs || [];
  if (!logs.length) return showToast("当前没有可导出的物资变动日志", true);
  downloadExcel(`办公资产-IT物资变动日志-${exportDateStamp()}.xls`, [
    {
      name: "物资变动日志",
      headers: ["时间", "增减", "设备类型", "品牌", "型号", "数量", "来源", "流向", "相关人员编号", "相关人员姓名", "标注"],
      rows: inventoryMovementLogExportRows(logs),
    },
  ]);
  showToast(`已导出 ${logs.length} 条物资变动日志`);
}

function exportInventoryMovementLogs() {
  const logs = state.inventoryMovementLogs || [];
  if (!logs.length) return showToast("当前没有可导出的物资变动日志", true);
  downloadExcel(`办公资产-IT物资变动日志-${exportDateStamp()}.xls`, [
    {
      name: "物资变动日志",
      headers: ["时间", "增减", "设备类型", "品牌", "型号", "数量", "来源", "流向", "相关人员编号", "相关人员姓名", "触发动作", "标注"],
      rows: inventoryMovementLogExportRows(logs),
    },
  ]);
  showToast(`已导出 ${logs.length} 条物资变动日志`);
}

function inventoryPurchaseLogExportRows(logs) {
  return [...logs]
    .sort((a, b) =>
      String(b.inboundDate || b.createdAt || "").localeCompare(String(a.inboundDate || a.createdAt || "")),
    )
    .map((log) => [
      log.inboundDate || "",
      log.typeName || "",
      log.brandName || "",
      log.modelName || "",
      log.quantity,
      log.cpu || "",
      log.memory || "",
      log.storage || "",
      log.gpu || "",
      log.sourceLabel || "",
      log.note || "",
      log.createdAt || "",
    ]);
}

function exportInventoryPurchaseLogs() {
  const logs = state.inventoryPurchaseLogs || [];
  if (!logs.length) return showToast("当前没有可导出的采购入库记录", true);
  const standardLogs = logs.filter((log) => !isComputerPurchaseLog(log));
  const computerLogs = logs.filter((log) => isComputerPurchaseLog(log));
  const sheets = [];
  if (standardLogs.length) {
    sheets.push({
      name: "普通物资入库",
      headers: ["入库日期", "物资类型", "品牌", "型号", "数量", "来源", "备注", "记录时间"],
      rows: standardLogs
        .sort((a, b) =>
          String(b.inboundDate || b.createdAt || "").localeCompare(String(a.inboundDate || a.createdAt || "")),
        )
        .map((log) => [
          log.inboundDate || "",
          log.typeName || "",
          log.brandName || "",
          log.modelName || "",
          log.quantity,
          log.sourceLabel || "",
          log.note || "",
          log.createdAt || "",
        ]),
    });
  }
  if (computerLogs.length) {
    sheets.push({
      name: "电脑入库",
      headers: ["入库日期", "品牌", "型号", "数量", "CPU", "内存", "存储", "显卡", "来源", "备注", "记录时间"],
      rows: computerLogs
        .sort((a, b) =>
          String(b.inboundDate || b.createdAt || "").localeCompare(String(a.inboundDate || a.createdAt || "")),
        )
        .map((log) => [
          log.inboundDate || "",
          log.brandName || "",
          log.modelName || "",
          log.quantity,
          log.cpu || "",
          log.memory || "",
          log.storage || "",
          log.gpu || "",
          log.sourceLabel || "",
          log.note || "",
          log.createdAt || "",
        ]),
    });
  }
  downloadExcel(`办公资产-IT物资采购入库-${exportDateStamp()}.xls`, sheets);
  showToast(`已导出 ${logs.length} 条采购入库记录`);
}

function exportSelectedEmployees() {
  const employees = sortEmployees(state.employees.filter((employee) => state.selectedEmployeeIds.includes(employee.id)));
  if (!employees.length) return showToast("请先选择至少一名使用人员", true);

  downloadExcel(`办公资产-使用人员-${exportDateStamp()}.xls`, [
    {
      name: "使用人员",
      headers: [
        "人员编号",
        "人员姓名",
        "所属组织",
        "组织路径",
        "部门",
        "岗位",
        "人员状态",
        "办公电脑",
        "显示屏",
        "其它配件",
        "邮箱",
        "手机号",
      ],
      rows: employeeExportRows(employees),
    },
    {
      name: "人员设备明细",
      headers: ["人员编号", "人员姓名", "组织路径", "设备类别", "设备名称", "型号或数量", "数量"],
      rows: employeeDeviceExportRows(employees),
    },
  ]);
  showToast(`已导出 ${employees.length} 名使用人员`);
}

function exportSelectedComputers() {
  const computers = state.computers.filter((computer) => state.selectedComputerIds.includes(computer.id));
  if (!computers.length) return showToast("请先选择至少一台办公电脑", true);

  downloadExcel(`办公资产-办公电脑-${exportDateStamp()}.xls`, [
    {
      name: "办公电脑",
      headers: [
        "设备名",
        "所属组织",
        "组织路径",
        "设备类型",
        "设备品牌",
        "型号",
        "CPU",
        "内存",
        "存储",
        "显卡",
        "固资编码",
        "购置日期",
        "注册日期",
        "SN/ST",
        "Wifi MAC",
        "网口 MAC",
        "位置",
        "部门",
        "使用用户",
        "IT资产状态",
      ],
      rows: computerExportRows(computers),
    },
  ]);
  showToast(`已导出 ${computers.length} 台办公电脑`);
}

function auditExportRows(logs) {
  return logs.map((log) => [
    log.createdAt || "",
    auditCategoryLabel(auditCategoryForLog(log)),
    auditChangeLabel(log),
    auditEntityTypeLabel(log.entityType),
    log.entityName || "",
    log.employeeId || "",
    log.employeeName || "",
    log.deviceName || "",
    auditValueText(log.oldValue),
    auditValueText(log.newValue),
    log.summary || "",
    log.actor || "",
    log.source || "",
  ]);
}

async function exportAuditLogs() {
  const payload = await requestJson(buildAuditLogsUrl(5000));
  const logs = Array.isArray(payload.logs) ? payload.logs : [];
  if (!logs.length) return showToast("当前筛选条件下没有可导出的日志", true);

  downloadExcel(`办公资产-操作日志-${exportDateStamp()}.xls`, [
    {
      name: "操作日志",
      headers: [
        "时间",
        "操作类别",
        "具体变动",
        "对象类别",
        "对象名称",
        "人员编号",
        "人员姓名",
        "设备名",
        "旧值",
        "新值",
        "说明",
        "操作人",
        "来源",
      ],
      rows: auditExportRows(logs),
    },
  ]);
  showToast(`已导出 ${logs.length} 条操作日志`);
}

function showToast(message, isError = false) {
  const root = document.querySelector("#toastRoot");
  const toast = document.createElement("div");
  toast.className = `toast${isError ? " error" : ""}`;
  toast.textContent = message;
  root.appendChild(toast);
  window.setTimeout(() => toast.remove(), 2600);
}

document.addEventListener("click", (event) => {
  const actionElement = event.target.closest("[data-action]");
  if (!actionElement) return;
  const action = actionElement.dataset.action;

  if (action === "logout") {
    logout();
    return;
  }

  if (action === "check-for-update") {
    handleUpdateCheck(actionElement);
    return;
  }

  if (action === "close-modal") {
    if (actionElement.classList.contains("modal-backdrop") && event.target !== actionElement) return;
    closeModal();
    return;
  }

  if (action === "toggle-employee-selection") {
    const employeeId = actionElement.dataset.id;
    const selected = new Set(state.selectedEmployeeIds);
    if (actionElement.checked) selected.add(employeeId);
    else selected.delete(employeeId);
    state.selectedEmployeeIds = [...selected];
    persistState(false);
    render();
    return;
  }

  if (action === "toggle-computer-selection") {
    const computerId = actionElement.dataset.id;
    const selected = new Set(state.selectedComputerIds);
    if (actionElement.checked) selected.add(computerId);
    else selected.delete(computerId);
    state.selectedComputerIds = [...selected];
    persistState(false);
    render();
    return;
  }

  if (action === "toggle-all-computers" || action === "select-all-computers") {
    const currentIds = getFilteredComputers().map((computer) => computer.id);
    const selected = new Set(state.selectedComputerIds);
    const allSelected = currentIds.length > 0 && currentIds.every((id) => selected.has(id));
    currentIds.forEach((id) => {
      if (allSelected) selected.delete(id);
      else selected.add(id);
    });
    state.selectedComputerIds = [...selected];
    persistState(false);
    render();
    return;
  }

  if (action === "clear-computer-selection") {
    state.selectedComputerIds = [];
    persistState(false);
    render();
    return;
  }

  if (action === "select-all-employees") {
    const selected = new Set(state.selectedEmployeeIds);
    getFilteredEmployees().forEach((employee) => selected.add(employee.id));
    state.selectedEmployeeIds = [...selected];
    persistState(false);
    render();
    return;
  }

  if (action === "clear-employee-selection") {
    state.selectedEmployeeIds = [];
    persistState(false);
    render();
    return;
  }

  if (action === "clear-employee-filters") {
    state.filters.employees = "";
    state.filters.employeeAssetSearch = "";
    state.filters.employeeStatus = "";
    state.filters.employeeOrg = "";
    state.filters.employeeDevice = "";
    syncEmployeeSearchDraftsFromFilters();
    persistState(false);
    render();
    return;
  }

  if (action === "apply-employee-search") {
    applyEmployeeSearchFilters();
    return;
  }

  if (action === "clear-inventory-filters") {
    state.filters.inventorySearch = "";
    state.filters.inventoryType = "";
    state.filters.inventoryBrand = "";
    persistState(false);
    render();
    return;
  }

  if (action === "export-employees") {
    exportSelectedEmployees();
    return;
  }

  if (action === "export-computers") {
    exportSelectedComputers();
    return;
  }

  if (action === "export-inventory") {
    exportInventory();
    return;
  }

  if (action === "export-inventory-purchase") {
    exportInventoryPurchaseLogs();
    return;
  }

  if (action === "export-inventory-log") {
    exportInventoryMovementLogs();
    return;
  }

  if (action === "refresh-audit") {
    refreshAuditLogs()
      .then(() => showToast("已刷新操作日志"))
      .catch((error) => {
        console.error("Unable to load audit logs", error);
        showToast(`日志加载失败：${error.message}`, true);
      });
    return;
  }

  if (action === "apply-audit-filters") {
    refreshAuditLogs()
      .then(() => showToast("已应用日志筛选"))
      .catch((error) => {
        console.error("Unable to apply audit filters", error);
        showToast(`日志筛选失败：${error.message}`, true);
      });
    return;
  }

  if (action === "export-audit") {
    exportAuditLogs().catch((error) => {
      console.error("Unable to export audit logs", error);
      showToast(`日志导出失败：${error.message}`, true);
    });
    return;
  }

  if (action === "navigate") {
    state.page = actionElement.dataset.page;
    persistState(false);
    render();
    if (state.page === "settings") {
      loadSettingsState({ users: isAdminUser() })
        .then(() => render())
        .catch((error) => {
          console.error("Unable to load settings", error);
          showToast(`设置加载失败：${error.message}`, true);
        });
    }
    if (state.page === "audit") {
      refreshAuditLogs({ silent: true })
        .then(() => render())
        .catch((error) => {
          console.error("Unable to load audit logs", error);
          showToast(`日志加载失败：${error.message}`, true);
        });
    }
    return;
  }

  if (action === "toggle-org") {
    const orgId = actionElement.dataset.id;
    setOrgExpanded(orgId, !isOrgExpanded(orgId));
    render();
    return;
  }

  if (action === "expand-all-orgs") {
    state.expandedOrgIds = state.orgs.map((org) => org.id);
    persistState(false);
    render();
    return;
  }

  if (action === "collapse-all-orgs") {
    state.expandedOrgIds = [];
    persistState(false);
    render();
    return;
  }

  if (action === "toggle-inventory-type") {
    const typeId = actionElement.dataset.id || "";
    setInventoryTypeExpanded(typeId, !isInventoryTypeExpanded(typeId));
    render();
    return;
  }

  if (action === "toggle-inventory-brand") {
    const brandId = actionElement.dataset.id || "";
    setInventoryBrandExpanded(brandId, !isInventoryBrandExpanded(brandId));
    render();
    return;
  }

  if (action === "expand-all-inventory") {
    expandVisibleInventoryNodes();
    render();
    return;
  }

  if (action === "collapse-all-inventory") {
    state.expandedInventoryTypeIds = [];
    state.expandedInventoryBrandIds = [];
    persistState(false);
    render();
    return;
  }

  if (action === "open-computer") openComputerModal(actionElement.dataset.id || "");
  if (action === "open-employee") openEmployeeModal(actionElement.dataset.id || "", actionElement.dataset.orgId || "");
  if (action === "create-database-backup") {
    handleDatabaseBackupCreate(actionElement);
    return;
  }
  if (action === "open-database-backup-download") {
    openDatabaseBackupDownloadModal(actionElement.dataset.id || "");
    return;
  }
  if (action === "open-settings-user") {
    openSettingsUserModal(actionElement.dataset.id || "");
    return;
  }
  if (action === "open-left-employee") {
    openLeftEmployeeModal(actionElement.dataset.id || "");
    return;
  }
  if (action === "manage-devices") openDeviceManager(actionElement.dataset.id);
  if (action === "open-org") openOrgModal(actionElement.dataset.id || "", actionElement.dataset.parentId || "");
  if (action === "open-type") openTypeModal(actionElement.dataset.id || "");
  if (action === "open-inventory-import") {
    openInventoryImportModal();
    return;
  }
  if (action === "open-inventory-brand") {
    openInventoryBrandModal(actionElement.dataset.typeId, actionElement.dataset.id || "");
    return;
  }
  if (action === "open-inventory-model") {
    openInventoryModelModal(actionElement.dataset.typeId, actionElement.dataset.brandId, actionElement.dataset.id || "");
    return;
  }
  if (action === "edit-inventory-log-note") {
    openInventoryMovementNoteModal(actionElement.dataset.id || "");
    return;
  }
  if (action === "commit-device-stock") {
    finishDeviceSave("deduct");
    return;
  }
  if (action === "commit-device-register") {
    finishDeviceSave("register");
    return;
  }
  if (action === "cancel-device-confirm") {
    pendingDeviceSave = null;
    closeModal();
    return;
  }
  if (action === "recover-selected-devices") {
    openDeviceRecoveryConfirm(actionElement.dataset.employeeId || "", actionElement.dataset.kind || "");
    return;
  }
  if (action === "confirm-device-recovery") {
    confirmDeviceRecovery();
    return;
  }
  if (action === "cancel-device-recovery") {
    const pending = pendingDeviceRecovery;
    pendingDeviceRecovery = null;
    closeModal();
    if (pending?.employeeId) openDeviceManager(pending.employeeId);
    return;
  }
  if (action === "confirm-leave-recovery") {
    confirmLeaveRecovery();
    return;
  }
  if (action === "cancel-leave-recovery") {
    pendingLeaveRecovery = null;
    closeModal();
    return;
  }
  if (action === "assign-computer") assignComputer(actionElement.dataset.employeeId);
  if (action === "release-computer") releaseComputer(actionElement.dataset.id, actionElement.dataset.employeeId);
  if (action === "edit-monitor") openDeviceManager(actionElement.dataset.employeeId);

  if (action === "add-monitor-module") {
    const employeeId = actionElement.dataset.employeeId;
    const list = document.querySelector(`[data-monitor-list="${CSS.escape(employeeId)}"]`);
    if (list) {
      list.insertAdjacentHTML("beforeend", renderMonitorModule(employeeId, {}, true));
      list.lastElementChild?.querySelector('input[name="brand"]')?.focus();
    }
    return;
  }

  if (action === "add-nonasset-module") {
    const employeeId = actionElement.dataset.employeeId;
    const list = document.querySelector(`[data-nonasset-list="${CSS.escape(employeeId)}"]`);
    const typeId = state.nonAssetTypes.find((type) => type.id === "mouse")?.id || state.nonAssetTypes[0]?.id || "mouse";
    if (list) {
      list.insertAdjacentHTML("beforeend", renderNonAssetModule(employeeId, { typeId, quantity: 1 }, true));
      list.lastElementChild?.querySelector('select[name="typeId"]')?.focus();
    }
    return;
  }

  if (action === "remove-device-module") {
    actionElement.closest(".device-module")?.remove();
    return;
  }

  if (action === "delete-computer") {
    const computer = state.computers.find((item) => item.id === actionElement.dataset.id);
    if (computer && window.confirm(`确定删除电脑 ${computer.deviceName} 吗？`)) {
      state.computers = state.computers.filter((item) => item.id !== computer.id);
      state.selectedComputerIds = state.selectedComputerIds.filter((id) => id !== computer.id);
      persistState(true);
      render();
      showToast("电脑已删除");
    }
  }

  if (action === "delete-employee") {
    const employee = getEmployee(actionElement.dataset.id);
    if (employee && window.confirm(`确定删除人员 ${employee.name} 吗？名下电脑会变为未分配。`)) {
      employeeRecoveryDevices(employee)
        .filter((device) => device.category !== "computer")
        .forEach((device) => {
          const matchedMonitor = (employee.monitors || []).find((item) => `monitor:${item.id}` === device.key);
          const matchedAsset = getNonAssetItems(employee).find((item) => `nonasset:${item.id}` === device.key);
          if (matchedMonitor?.stockAdjusted || matchedAsset?.stockAdjusted) {
            returnDeviceToInventory(device, {
              sourceLabel: employeeLogLabel(employee.employeeNo, employee.name),
              targetLabel: "IT物资库存",
              note: "删除人员时回收入库",
              relatedEmployeeNo: employee.employeeNo || "",
              relatedEmployeeName: employee.name || "",
              triggerAction: "employee_delete_recovery",
            });
          }
        });
      state.computers.forEach((computer) => {
        if (computer.userId === employee.id) {
          computer.userId = null;
          computer.status = "idle";
        }
      });
      state.employees = state.employees.filter((item) => item.id !== employee.id);
      state.selectedEmployeeIds = state.selectedEmployeeIds.filter((id) => id !== employee.id);
      normalizeComputersAgainstEmployees();
      persistState(true);
      render();
      showToast("人员已删除");
    }
  }

  if (action === "delete-monitor") {
    const employee = getEmployee(actionElement.dataset.employeeId);
    if (employee && window.confirm("确定删除这条显示屏记录吗？")) {
      const removed = (employee.monitors || []).find((monitor) => monitor.id === actionElement.dataset.id);
      if (removed?.stockAdjusted) {
        returnDeviceToInventory({
          category: "monitor",
          quantity: 1,
          typeId: removed.typeId || defaultMonitorTypeId(),
          typeName: getType(removed.typeId || defaultMonitorTypeId())?.name || "显示屏",
          brand: removed.brand || "",
          model: removed.model || "",
          brandId: removed.inventoryBrandId || "",
          modelId: removed.inventoryModelId || "",
        }, {
          sourceLabel: employeeLogLabel(employee.employeeNo, employee.name),
          targetLabel: "IT物资库存",
          note: "删除显示屏记录回收入库",
          relatedEmployeeNo: employee.employeeNo || "",
          relatedEmployeeName: employee.name || "",
          triggerAction: "delete_monitor",
        });
      }
      employee.monitors = employee.monitors.filter((monitor) => monitor.id !== actionElement.dataset.id);
      persistState(true);
      openDeviceManager(employee.id);
      render();
      showToast("显示屏记录已删除");
    }
  }

  if (action === "delete-nonasset") {
    const employee = getEmployee(actionElement.dataset.employeeId);
    if (employee && window.confirm("确定删除这条非资产设备记录吗？")) {
      const removed = getNonAssetItems(employee).find((item) => item.id === actionElement.dataset.id);
      if (removed?.stockAdjusted) {
        returnDeviceToInventory({
          category: "non-asset",
          quantity: Math.max(1, Number(removed.quantity || 1)),
          typeId: removed.typeId,
          typeName: getType(removed.typeId)?.name || "非资产设备",
          brand: removed.brand || "",
          model: removed.model || "",
          brandId: removed.inventoryBrandId || "",
          modelId: removed.inventoryModelId || "",
        }, {
          sourceLabel: employeeLogLabel(employee.employeeNo, employee.name),
          targetLabel: "IT物资库存",
          note: "删除非资产设备记录回收入库",
          relatedEmployeeNo: employee.employeeNo || "",
          relatedEmployeeName: employee.name || "",
          triggerAction: "delete_nonasset",
        });
      }
      employee.nonAssetItems = getNonAssetItems(employee).filter((item) => item.id !== actionElement.dataset.id);
      syncNonAssetAggregate(employee);
      persistState(true);
      openDeviceManager(employee.id);
      render();
      showToast("非资产设备记录已删除");
    }
  }

  if (action === "delete-org") {
    const org = getOrg(actionElement.dataset.id);
    if (org && window.confirm(`确定删除组织 ${org.name} 吗？直接挂在该组织上的记录会变为未分配，下级组织会提升为根组织。`)) {
      state.employees.forEach((employee) => {
        if (employee.orgId === org.id) employee.orgId = "";
      });
      state.computers.forEach((computer) => {
        if (computer.orgId === org.id) computer.orgId = "";
      });
      state.orgs.forEach((item) => {
        if (item.parentId === org.id) item.parentId = "";
      });
      state.orgs = state.orgs.filter((item) => item.id !== org.id);
      state.expandedOrgIds = state.expandedOrgIds.filter((id) => id !== org.id);
      persistState(true);
      render();
      showToast("组织已删除");
    }
  }

  if (action === "delete-type") {
    const type = getType(actionElement.dataset.id);
    if (!type) return;
    if (isProtectedInventoryType(type)) {
      return showToast("电脑类型为系统保留分组，不能删除。", true);
    }
    const assignedCount = state.employees.reduce((sum, employee) => {
      const monitorCount = (employee.monitors || []).filter((item) => item.typeId === type.id).length;
      const nonAssetCount = getNonAssetItems(employee).filter((item) => item.typeId === type.id).length;
      return sum + monitorCount + nonAssetCount;
    }, 0);
    if (assignedCount > 0) {
      return showToast(`类型 ${type.name} 仍被 ${assignedCount} 条人员设备记录引用，无法删除。`, true);
    }
    const stockCount =
      state.inventoryBrands.filter((item) => item.typeId === type.id).length +
      state.inventoryModels.filter((item) => item.typeId === type.id).length;
    if (
      stockCount > 0 &&
      !window.confirm(`类型 ${type.name} 下还有 ${stockCount} 条库存记录，确认删除吗？删除后将同步清理下级品牌和型号。`)
    ) {
      return;
    }
      state.inventoryModels
        .filter((item) => item.typeId === type.id && Number(item.quantity || 0) > 0)
        .forEach((item) => {
          const brand = getInventoryBrand(item.brandId);
          recordInventoryMovement({
            direction: "decrease",
            typeName: type.name,
            brandName: brand?.name || "",
            modelName: item.name || "",
            quantity: Math.max(1, Number(item.quantity || 0)),
            sourceLabel: "IT物资库存",
            targetLabel: "删除设备类型",
            note: "删除类型时清空库存",
            triggerAction: "delete_type",
          });
        });
      const removedBrandIds = new Set(
        state.inventoryBrands.filter((item) => item.typeId === type.id).map((item) => item.id),
      );
      state.inventoryModels = state.inventoryModels.filter(
        (item) => item.typeId !== type.id && !removedBrandIds.has(item.brandId),
      );
      state.inventoryBrands = state.inventoryBrands.filter((item) => item.typeId !== type.id);
      state.nonAssetTypes = state.nonAssetTypes.filter((item) => item.id !== type.id);
      state.expandedInventoryTypeIds = state.expandedInventoryTypeIds.filter((id) => id !== type.id);
      state.expandedInventoryBrandIds = state.expandedInventoryBrandIds.filter((id) => !removedBrandIds.has(id));
      persistState(true);
      render();
      showToast("设备类型已删除");
  }

  if (action === "delete-inventory-brand") {
    const brand = getInventoryBrand(actionElement.dataset.id);
    const models = brand ? inventoryModelsForBrand(brand.id) : [];
    if (!brand) return;
    if (models.length) return showToast("请先删除或迁移该品牌下的全部型号。", true);
    const brandInUse = state.employees.some(
      (employee) =>
        (employee.monitors || []).some((item) => item.inventoryBrandId === brand.id) ||
        getNonAssetItems(employee).some((item) => item.inventoryBrandId === brand.id),
    );
    if (brandInUse) return showToast("该品牌仍被人员名下物资引用，无法删除。", true);
    if (!window.confirm(`确定删除库存品牌 ${brand.name} 吗？`)) return;
    state.inventoryBrands = state.inventoryBrands.filter((item) => item.id !== brand.id);
    state.expandedInventoryBrandIds = state.expandedInventoryBrandIds.filter((id) => id !== brand.id);
    persistState(true);
    render();
    showToast("库存品牌已删除");
  }

  if (action === "delete-inventory-model") {
    const model = getInventoryModel(actionElement.dataset.id);
    const modelInUse = state.employees.some(
      (employee) =>
        (employee.monitors || []).some((item) => item.inventoryModelId === model?.id) ||
        getNonAssetItems(employee).some((item) => item.inventoryModelId === model?.id),
    );
    if (modelInUse) return showToast("该型号仍被人员名下物资引用，无法删除。", true);
    if (!model || !window.confirm(`确定删除库存型号 ${model.name} 吗？`)) return;
    if (Number(model.quantity || 0) > 0) {
      const brand = getInventoryBrand(model.brandId);
      const type = getType(model.typeId);
      recordInventoryMovement({
        direction: "decrease",
        typeName: type?.name || "",
        brandName: brand?.name || "",
        modelName: model.name || "",
        quantity: Math.max(1, Number(model.quantity || 0)),
        sourceLabel: "IT物资库存",
        targetLabel: "删除型号",
        note: "删除型号时清空库存",
        triggerAction: "delete_inventory_model",
      });
    }
    state.inventoryModels = state.inventoryModels.filter((item) => item.id !== model.id);
    persistState(true);
    render();
    showToast("库存型号已删除");
  }

  if (action === "reset-data" && window.confirm("确定从数据库重新加载吗？当前页面未保存的改动会被覆盖。")) {
    hydrateStateFromServer({ toast: true });
  }
});

document.addEventListener("submit", (event) => {
  const form = event.target.closest("form[data-form]");
  if (!form) return;

  event.preventDefault();
  const type = form.dataset.form;

  if (type === "auth-login" || type === "auth-bootstrap") {
    handleAuthSubmit(form);
    return;
  }
  if (type === "system-settings") {
    handleSystemSettingsSubmit(form);
    return;
  }
  if (type === "backup-schedule") {
    handleBackupScheduleSubmit(form);
    return;
  }
  if (type === "database-backup-download") {
    handleDatabaseBackupDownloadSubmit(form);
    return;
  }
  if (type === "change-password") {
    handleChangePasswordSubmit(form);
    return;
  }
  if (type === "user-account") {
    handleUserAccountSubmit(form);
    return;
  }
  if (type === "computer") handleComputerSubmit(form);
  if (type === "employee") handleEmployeeSubmit(form);
  if (type === "monitor") handleMonitorSubmit(form);
  if (type === "nonasset") handleNonAssetSubmit(form);
  if (type === "org") handleOrgSubmit(form);
  if (type === "type") handleTypeSubmit(form);
  if (type === "inventory-brand") handleInventoryBrandSubmit(form);
  if (type === "inventory-model") handleInventoryModelSubmit(form);
  if (type === "inventory-import") handleInventoryImportSubmit(form);
  if (type === "inventory-log-note") handleInventoryMovementNoteSubmit(form);
  if (type === "inventory-purchase-note") handleInventoryPurchaseNoteSubmit(form);
});

document.addEventListener("change", (event) => {
  const inventoryImportForm = event.target.closest('form[data-form="inventory-import"]');
  if (inventoryImportForm && event.target.name === "type") {
    toggleInventoryImportComputerFields(inventoryImportForm);
  }
  const computerForm = event.target.closest('form[data-form="computer"]');
  if (computerForm && ["computerInventoryBrandId", "computerInventoryModelId"].includes(event.target.name)) {
    updateComputerInventorySelectors(computerForm, event.target.name);
    return;
  }
  const deviceForm = event.target.closest('form[data-form="monitor"], form[data-form="nonasset"]');
  if (deviceForm && ["typeId", "brandId", "modelId"].includes(event.target.name)) {
    updateDeviceInventorySelectors(deviceForm, event.target.name);
    return;
  }
  const employeeForm = event.target.closest('form[data-form="employee"]');
  if (employeeForm && event.target.name === "orgId") {
    const numberInput = employeeForm.querySelector('input[name="employeeNo"]');
    if (
      numberInput &&
      (numberInput.dataset.generated === "true" ||
        numberInput.value === (numberInput.dataset.originalNumber || ""))
    ) {
      numberInput.value = employeeNumberFor(event.target.value, employeeForm.dataset.id || "");
      numberInput.dataset.generated = "true";
    }
  }
  if (employeeForm && event.target.name === "status") {
    toggleEmployeeLeaveFields(employeeForm, true);
    return;
  }
  const orgForm = event.target.closest('form[data-form="org"]');
  if (orgForm && ["name", "parentId"].includes(event.target.name)) {
    const codeInput = orgForm.querySelector('input[name="code"]');
    if (
      codeInput &&
      (!codeInput.value ||
        codeInput.dataset.generated === "true" ||
        codeInput.value.toUpperCase() === (codeInput.dataset.originalCode || "").toUpperCase())
    ) {
      codeInput.value = orgCodeFor(
        { id: orgForm.dataset.id || "", name: orgForm.elements.name?.value || "" },
        orgForm.elements.parentId?.value || "",
        orgForm.dataset.id || "",
      );
      codeInput.dataset.generated = "true";
    }
  }
  const filter = event.target.closest("[data-filter]");
  if (!filter) return;
  state.filters[filter.dataset.filter] = filter.value;
  if (filter.dataset.filter === "inventoryType") {
    const selectedBrand = getInventoryBrand(state.filters.inventoryBrand || "");
    if (selectedBrand && selectedBrand.typeId !== filter.value) {
      state.filters.inventoryBrand = "";
    }
    expandVisibleInventoryNodes();
  }
  if (filter.dataset.filter === "inventoryBrand") {
    const brand = getInventoryBrand(filter.value);
    if (brand) {
      state.filters.inventoryType = brand.typeId;
      ensureInventoryExpanded(brand.typeId, brand.id);
    }
    expandVisibleInventoryNodes();
  }
  persistState(false);
  if (String(filter.dataset.filter).startsWith("audit")) {
    queueAuditLogRefresh();
    return;
  }
  render();
});

document.addEventListener("input", (event) => {
  const inventoryImportForm = event.target.closest('form[data-form="inventory-import"]');
  if (inventoryImportForm && event.target.name === "type") {
    toggleInventoryImportComputerFields(inventoryImportForm);
  }
  const computerForm = event.target.closest('form[data-form="computer"]');
  if (computerForm && ["wifiMac", "ethernetMac"].includes(event.target.name)) {
    const normalized = normalizeMacAddress(event.target.value);
    if (normalized !== String(event.target.value || "").trim()) {
      event.target.value = normalized;
    }
  }
  const employeeForm = event.target.closest('form[data-form="employee"]');
  if (employeeForm && event.target.name === "employeeNo") {
    event.target.dataset.generated = "false";
  }
  const orgForm = event.target.closest('form[data-form="org"]');
  if (orgForm && event.target.name === "code") {
    event.target.dataset.generated = "false";
  }
  if (orgForm && event.target.name === "name") {
    const codeInput = orgForm.querySelector('input[name="code"]');
    if (
      codeInput &&
      (codeInput.dataset.generated === "true" ||
        codeInput.value.toUpperCase() === (codeInput.dataset.originalCode || "").toUpperCase())
    ) {
      codeInput.value = orgCodeFor(
        { id: orgForm.dataset.id || "", name: event.target.value },
        orgForm.elements.parentId?.value || "",
        orgForm.dataset.id || "",
      );
      codeInput.dataset.generated = "true";
    }
  }
});

document.addEventListener("input", (event) => {
  const filter = event.target.closest("[data-filter]");
  if (!filter) return;
  if (!["auditSearch", "auditEmployee", "inventorySearch", "employees", "employeeAssetSearch"].includes(filter.dataset.filter)) return;
  if (["employees", "employeeAssetSearch"].includes(filter.dataset.filter)) {
    employeeSearchDrafts[filter.dataset.filter] = filter.value;
    return;
  }
  state.filters[filter.dataset.filter] = filter.value;
  persistState(false);
  if (filter.dataset.filter === "inventorySearch") {
    if (filter.value) expandVisibleInventoryNodes();
    renderPreservingFilterInput(filter.dataset.filter);
  }
});

document.addEventListener("keydown", (event) => {
  const employeeSearchFilter = event.target.closest('[data-filter="employees"], [data-filter="employeeAssetSearch"]');
  if (employeeSearchFilter && event.key === "Enter") {
    event.preventDefault();
    employeeSearchDrafts[employeeSearchFilter.dataset.filter] = employeeSearchFilter.value;
    applyEmployeeSearchFilters();
    return;
  }
  if (event.key === "Escape" && document.querySelector("#modalRoot").innerHTML) closeModal();
});

startAuth();
