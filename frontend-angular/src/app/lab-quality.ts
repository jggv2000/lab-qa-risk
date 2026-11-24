// Roles disponibles en la aplicación de laboratorio
export type UserRole = 'viewer' | 'customer' | 'admin';

// Niveles de riesgo definidos para el laboratorio basado en riesgo
export type RiskLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

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
}

// Matriz de permisos por rol (alineada con el backend)
export function getPermissionsForRole(role: UserRole): RolePermissions {
  switch (role) {
    case 'admin':
      return {
        canViewAllOrders: true,
        canCreateOrder: true,
        canChangeStatus: true,
        canDeleteOrder: true,
      };
    case 'customer':
      return {
        canViewAllOrders: false,
        canCreateOrder: true,
        canChangeStatus: false,
        canDeleteOrder: false,
      };
    case 'viewer':
    default:
      return {
        canViewAllOrders: true,
        canCreateOrder: false,
        canChangeStatus: false,
        canDeleteOrder: false,
      };
  }
}

// Validación básica de entrada en frontend antes de enviar a la API
export function validateOrderInput(input: OrderInput): string[] {
  const errors: string[] = [];
  if (!input.customerEmail || !input.customerEmail.includes('@')) {
    errors.push('Correo de cliente inválido');
  }
  if (input.amount <= 0) {
    errors.push('El importe debe ser mayor que cero');
  }
  if (input.discountPct < 0 || input.discountPct > 100) {
    errors.push('El descuento debe estar entre 0 y 100');
  }
  return errors;
}

// Regla de apoyo para exigir revisión humana ante alertas GDPR o riesgo alto/crítico
export function requiresManualReview(riskLevel: RiskLevel, gdprAlert: boolean): boolean {
  return gdprAlert || riskLevel === 'HIGH' || riskLevel === 'CRITICAL';
}
