# Python Coding Standards
# .gemini/standards/python.md

## Core Standards

Follow:
- **PEP 8** — style, line length (88 chars with Black), import order
- **Type hints required** — all function signatures, public APIs, and class attributes
- **`dataclasses` or `pydantic`** for data models — never plain dicts for structured data
- **Dependency injection** for services — never instantiate dependencies inside functions
- **No global mutable state** — use configuration objects or dependency containers
- **`logging` module** — never `print()` in production code
- **Explicit exceptions** — never silent failures, never bare `except:`

## Project Structure

```
src/
├── domain/           ← Pure Python, no framework imports
├── application/      ← Use cases, depends only on domain interfaces
├── infrastructure/   ← SQLAlchemy, httpx, boto3 — implements domain interfaces
├── interfaces/       ← FastAPI routers, CLI commands
└── config/           ← Settings via pydantic BaseSettings
```

## Models

```python
# ✅ Correct — pydantic model with types
class UserRegistration(BaseModel):
    email: EmailStr
    password: SecretStr
    display_name: str

# ❌ Wrong — untyped dict
def register(data: dict):
    ...
```

## Naming

```python
# ✅ Domain-meaningful
user_repository: UserRepository
auth_token: JWTToken
invoice_calculator: InvoiceCalculator
retry_policy: ExponentialBackoffPolicy

# ❌ Generic / AI-style
data, info, result, temp
process_data(), handle_stuff(), do_thing()
```

## Error Handling

```python
# ✅ Explicit, typed exceptions
class PaymentDeclinedError(DomainError):
    def __init__(self, reason: str) -> None:
        super().__init__(f"Payment declined: {reason}")

# ❌ Silent failure
try:
    process_payment()
except Exception:
    pass
```

## Comments

```python
# ✅ Explains non-obvious business rule
# Stripe requires idempotency keys to safely retry failed charges
charge = stripe.create_charge(idempotency_key=order.id)

# ❌ Describes what the code does (obvious)
# Create the charge
charge = stripe.create_charge(...)
```

## Testing

- **pytest** — fixtures, parametrize, no unittest
- **Meaningful assertions** — assert specific values, not just truthiness
- **Fixtures for dependencies** — never instantiate services inside tests directly
- **Coverage target** — 80%+ for application layer, 100% for domain

```python
# ✅ Meaningful test
def test_invoice_total_applies_tax_to_subtotal(invoice_factory):
    invoice = invoice_factory.create(subtotal=Money(100, "USD"), tax_rate=0.1)
    assert invoice.total == Money(110, "USD")

# ❌ Weak assertion
def test_invoice():
    result = create_invoice(data)
    assert result is not None
```
