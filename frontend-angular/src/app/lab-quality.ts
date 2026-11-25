// Roles disponibles en la aplicación de laboratorio
export type UserRole = 'viewer' | 'cliente' | 'customer' | 'admin';

// Niveles de riesgo definidos para el laboratorio basado en riesgo
export type RiskLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

// Modo visual de interfaz
export type ThemeMode = 'dark' | 'light';

export interface OrderInput {
  customerEmail: string;
  amount: number;
  discountPct: number;
  marketingConsent: boolean;
  notes: string;
}

export interface RolePermissions {
  canViewAllOrders: boolean;
  canCreateOrder: boolean;
  canChangeStatus: boolean;
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

// Matriz de permisos por rol (alineada con el backend y las flags de versión)
export function getPermissionsForRole(
  role: UserRole,
  flags: VersionDefectFlags = {}
): RolePermissions {
  const normalizedRole = role === 'customer' ? 'cliente' : role;

  switch (normalizedRole) {
    case 'admin':
      return {
        canViewAllOrders: true,
        canCreateOrder: true,
        canChangeStatus: true,
        canDeleteOrder: true,
        canManageUsers: true,
        canManageAdminTools: true,
      };
    case 'cliente':
      return {
        canViewAllOrders: false,
        canCreateOrder: true,
        canChangeStatus: false,
        canDeleteOrder: Boolean(flags.broken_order_workflow),
        canManageUsers: false,
        canManageAdminTools: false,
      };
    case 'viewer':
    default: {
      const canModify = Boolean(flags.viewer_can_modify);
      return {
        canViewAllOrders: true,
        canCreateOrder: canModify,
        canChangeStatus: canModify,
        canDeleteOrder: canModify,
        canManageUsers: Boolean(flags.broken_rbac_escalation),
        canManageAdminTools: Boolean(flags.broken_rbac_escalation),
      };
    }
  }
}

// Validación básica de entrada en frontend antes de enviar a la API
export function validateOrderInput(input: OrderInput): string[] {
  const errors: string[] = [];

  if (!input.customerEmail || !EMAIL_RE.test(input.customerEmail.trim())) {
    errors.push('Correo de cliente inválido');
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

// Regla de apoyo para exigir revisión humana ante alertas GDPR o riesgo alto/crítico
export function requiresManualReview(riskLevel: RiskLevel, gdprAlert: boolean): boolean {
  return gdprAlert || riskLevel === 'HIGH' || riskLevel === 'CRITICAL';
}

// Alternancia entre modo oscuro y modo claro
export function getNextThemeMode(currentMode: ThemeMode): ThemeMode {
  return currentMode === 'dark' ? 'light' : 'dark';
}
