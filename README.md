# capbound — Capped Permit Generator & Allowance Auditor

**capbound** помогает держать кошелёк в безопасности:
- сканирует allowance для ваших ERC-20 и показывает рисковые «бесконечные» разрешения;
- генерирует **ограниченные** и **временные** EIP-2612 `permit` (cap + deadline) **офлайн**;
- формирует raw-транзакции на отзыв `approve(spender, 0)` там, где `permit` отсутствует.

> Идея проста: давайте перестанем выдавать бесконечные разрешения и начнём делиться **точно дозированными** permit'ами, действующими 10–30 минут.

## Установка

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
