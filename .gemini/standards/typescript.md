# TypeScript Coding Standards
# .gemini/standards/typescript.md

## Core Standards

Follow:
- **Strict mode** — `"strict": true` in `tsconfig.json`, no exceptions
- **Interfaces for contracts** — define shapes as interfaces, not inline types
- **Zod or Valibot** for runtime validation of external input (API, forms, env)
- **Service layer pattern** — business logic never leaks into controllers/components
- **No `any` type** — if necessary, document why with an inline comment
- **Functional core, imperative shell** — pure functions for logic, effects at the boundary
- **`Result` types or typed errors** over thrown exceptions for expected failures

## Project Structure

```
src/
├── domain/           ← Types, entities, value objects — no runtime dependencies
├── application/      ← Use cases, service interfaces
├── infrastructure/   ← DB, APIs, external — implements application interfaces
├── interfaces/       ← Express routes, React components, CLI — calls application layer
└── config/           ← Typed env config via Zod
```

## Types and Interfaces

```typescript
// ✅ Named interface with intent
interface UserRegistrationRequest {
  email: string;
  password: string;
  displayName: string;
}

// ❌ Inline type with generic name
function register(data: { email: string; password: string }) {}

// ❌ Any type
function process(input: any): any {}
```

## Naming

```typescript
// ✅ Domain-meaningful
const userRepository: UserRepository
const authToken: JWTToken
const orderSummary: OrderSummary
const retryPolicy: ExponentialBackoffPolicy

// ❌ Generic / AI-style
const data, info, result, temp
function processData(), handleStuff(), doThing()
```

## Validation (Zod)

```typescript
// ✅ Schema-validated external input
const CreateOrderSchema = z.object({
  customerId: z.string().uuid(),
  lineItems: z.array(LineItemSchema).min(1),
  currency: z.enum(["USD", "EUR", "GBP"]),
});

type CreateOrderRequest = z.infer<typeof CreateOrderSchema>;
```

## Error Handling

```typescript
// ✅ Typed result — no unexpected throws
type Result<T, E> = { ok: true; value: T } | { ok: false; error: E };

async function chargePayment(
  order: Order
): Promise<Result<PaymentReceipt, PaymentError>> {
  ...
}

// ❌ Throw for expected failure
function chargePayment(order: Order): PaymentReceipt {
  throw new Error("Payment failed"); // caller doesn't know this throws
}
```

## Comments

```typescript
// ✅ Explains non-obvious constraint
// Stripe delivery guarantees exactly-once only with idempotency keys
const charge = await stripe.charges.create(payload, {
  idempotencyKey: order.id,
});

// ❌ States the obvious
// Create the charge
const charge = await stripe.charges.create(payload);
```

## Testing

- **Vitest** (preferred) or **Jest**
- **No `any` in test files**
- **Factory functions** for test data — never raw object literals repeated across tests
- **Mock at the boundary** — mock infrastructure, not domain logic

```typescript
// ✅ Descriptive, specific assertion
it("applies tax to order subtotal when tax rate is configured", () => {
  const order = orderFactory.create({ subtotal: 100, taxRate: 0.1 });
  expect(order.total).toBe(110);
});

// ❌ Generic, weak assertion
it("calculates order total", () => {
  expect(result).toBeDefined();
});
```
