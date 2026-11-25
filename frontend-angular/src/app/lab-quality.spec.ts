export type LabRole = 'admin' | 'cliente' | 'customer' | 'viewer';
export type RiskLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export interface OrderInput {
  customerEmail: string;
  amount: number;
  discountPct: number;
  marketingConsent: boolean;
  notes?: string;
}

export interface RolePermissions {
  canViewOrders: boolean;
  canCreateOrder: boolean;
  canApproveOrder: boolean;
  canDeleteOrder: boolean;
  canManageUsers: boolean;
  canManageAdminTools: boolean;
}

export interface VersionDefectFlags {
  viewer_can_modify?: boolean;
  broken_order_workflow?: boolean;
  broken_rbac_escalation?: boolean;
  pii_exposure_or_no_rgpd?: boolean;
  weak_field_validation?: boolean;
}

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export function validateOrderInput(input: OrderInput): string[] {
  const errors: string[] = [];

  if (!input.customerEmail || !EMAIL_RE.test(input.customerEmail.trim())) {
    errors.push('Correo electrónico no válido');
  }

  if (typeof input.amount !== 'number' || Number.isNaN(input.amount) || input.amount <= 0) {
    errors.push('El importe debe ser mayor que cero');
  }

  if (
    typeof input.discountPct !== 'number' ||
    Number.isNaN(input.discountPct) ||
    input.discountPct < 0 ||
    input.discountPct > 100
  ) {
    errors.push('El descuento debe estar entre 0 y 100');
  }

  return errors;
}

export function getPermissionsForRole(
  role: LabRole,
  flags: VersionDefectFlags = {}
): RolePermissions {
  const normalizedRole = role === 'customer' ? 'cliente' : role;

  if (normalizedRole === 'admin') {
    return {
      canViewOrders: true,
      canCreateOrder: true,
      canApproveOrder: true,
      canDeleteOrder: true,
      canManageUsers: true,
      canManageAdminTools: true,
    };
  }

  if (normalizedRole === 'cliente') {
    return {
      canViewOrders: true,
      canCreateOrder: true,
      canApproveOrder: false,
      canDeleteOrder: false,
      canManageUsers: false,
      canManageAdminTools: false,
    };
  }

  const canModify = Boolean(flags.viewer_can_modify);
  return {
    canViewOrders: true,
    canCreateOrder: canModify,
    canApproveOrder: canModify,
    canDeleteOrder: canModify,
    canManageUsers: false,
    canManageAdminTools: false,
  };
}

export function requiresManualReview(riskLevel: RiskLevel, gdprAlert: boolean): boolean {
  if (gdprAlert) {
    return true;
  }
  return riskLevel === 'HIGH' || riskLevel === 'CRITICAL';
}

export function toggleThemeMode(isLightMode: boolean): 'light' | 'dark' {
  return isLightMode ? 'light' : 'dark';
}
