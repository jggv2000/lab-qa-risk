import {
  getPermissionsForRole,
  requiresManualReview,
  validateOrderInput,
} from './lab-quality';

describe('Pearson QA Risk Lab - Frontend Logic', () => {
  it('debe validar una entrada correcta sin errores', () => {
    const errors = validateOrderInput({
      customerEmail: 'cliente1@ejemplo.com',
      amount: 250,
      discountPct: 10,
      marketingConsent: true,
      notes: 'Pedido estándar',
    });
    expect(errors.length).toBe(0);
  });

  it('debe detectar valores inválidos o fuera de rango', () => {
    const errors = validateOrderInput({
      customerEmail: 'correo-no-valido',
      amount: -10,
      discountPct: 150,
      marketingConsent: false,
      notes: '',
    });
    expect(errors.length).toBe(3);
  });

  it('debe aplicar correctamente los permisos para viewer, customer y admin', () => {
    expect(getPermissionsForRole('viewer').canCreateOrder).toBeFalse();
    expect(getPermissionsForRole('customer').canCreateOrder).toBeTrue();
    expect(getPermissionsForRole('customer').canDeleteOrder).toBeFalse();
    expect(getPermissionsForRole('admin').canDeleteOrder).toBeTrue();
  });

  it('debe exigir revisión manual cuando haya alerta GDPR o riesgo HIGH/CRITICAL', () => {
    expect(requiresManualReview('LOW', false)).toBeFalse();
    expect(requiresManualReview('LOW', true)).toBeTrue();
    expect(requiresManualReview('HIGH', false)).toBeTrue();
    expect(requiresManualReview('CRITICAL', false)).toBeTrue();
  });
});
