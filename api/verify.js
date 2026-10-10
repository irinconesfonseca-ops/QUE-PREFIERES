
import { scrypt, randomBytes, timingSafeEqual } from "node:crypto";
import { promisify } from "node:util";

const scryptAsync = promisify(scrypt);

function json(res, status, data) {
  res.status(status).json(data);
}

function getEnv(name) {
  return process.env[name];
}

async function hashPassword(value) {
  const salt = randomBytes(16).toString("hex");
  const key = await scryptAsync(value, salt, 64);
  return `${salt}:${Buffer.from(key).toString("hex")}`;
}

async function checkPassword(value, stored) {
  if (typeof value !== "string" || !stored) return false;

  const parts = stored.split(":");
  if (parts.length !== 2) return false;

  const [salt, hash] = parts;
  const key = Buffer.from(
    await scryptAsync(value, salt, 64)
  );
  const expected = Buffer.from(hash, "hex");

  return key.length === expected.length &&
    timingSafeEqual(key, expected);
}

async function dbRequest(path, options = {}) {
  const url = getEnv("SUPABASE_URL");
  const key = getEnv("SUPABASE_SERVICE_ROLE_KEY");

  if (!url || !key) {
    throw new Error("Faltan variables del servidor");
  }

  return fetch(`${url}/rest/v1/${path}`, {
    ...options,
    headers: {
      apikey: key,
      Authorization: `Bearer ${key}`,
      "Content-Type": "application/json",
      "Accept-Profile": "private",
      "Content-Profile": "private",
      ...(options.headers || {}),
    },
  });
}

export default async function handler(req, res) {
  if (req.method !== "POST") {
    return json(res, 405, { error: "Método no permitido" });
  }

  try {
    const { action, pin, adminPassword, newPin, newAdminPassword,
      setupSecret } = req.body || {};

    const response = await dbRequest(
      "game_security?select=id,pin_hash,admin_password_hash"
    );

    if (!response.ok) {
      return json(res, 500, {
        error: "No se pudo consultar la seguridad de la base de datos"
      });
    }

    const rows = await response.json();
    const current = rows[0];

    if (action === "setup") {
      if (!getEnv("SETUP_SECRET") ||
          setupSecret !== getEnv("SETUP_SECRET")) {
        return json(res, 403, { error: "Acceso denegado" });
      }

      if (current) {
        return json(res, 409, {
          error: "La configuración inicial ya existe"
        });
      }

      if (typeof pin !== "string" || pin.length < 4 ||
          typeof adminPassword !== "string" ||
          adminPassword.length < 12) {
        return json(res, 400, {
          error: "El PIN debe tener 4 caracteres y la contraseña 12"
        });
      }

      const result = await dbRequest("game_security", {
        method: "POST",
        headers: { Prefer: "return=minimal" },
        body: JSON.stringify([{
          id: 1,
          pin_hash: await hashPassword(pin),
          admin_password_hash: await hashPassword(adminPassword)
        }])
      });

      if (!result.ok) {
        return json(res, 500, { error: "No se pudo guardar la configuración" });
      }

      return json(res, 200, { ok: true });
    }

    if (!current) {
      return json(res, 409, {
        error: "Primero debes configurar el acceso"
      });
    }

    if (action === "verify-pin") {
      const ok = await checkPassword(pin, current.pin_hash);
      return json(res, 200, { ok });
    }

    if (action === "admin-login") {
      const ok = await checkPassword(
        adminPassword,
        current.admin_password_hash
      );
      return json(res, 200, { ok });
    }

    if (action === "change-pin" || action === "change-admin-password") {
      const authorized = await checkPassword(
        adminPassword,
        current.admin_password_hash
      );

      if (!authorized) {
        return json(res, 403, { error: "Contraseña incorrecta" });
      }

      const changes = {};

      if (action === "change-pin") {
        if (typeof newPin !== "string" || newPin.length < 4) {
          return json(res, 400, { error: "PIN no válido" });
        }
        changes.pin_hash = await hashPassword(newPin);
      } else {
        if (typeof newAdminPassword !== "string" ||
            newAdminPassword.length < 12) {
          return json(res, 400, {
            error: "Usa una contraseña de al menos 12 caracteres"
          });
        }
        changes.admin_password_hash =
          await hashPassword(newAdminPassword);
      }

      const result = await dbRequest("game_security?id=eq.1", {
        method: "PATCH",
        headers: { Prefer: "return=minimal" },
        body: JSON.stringify(changes)
      });

      if (!result.ok) {
        return json(res, 500, { error: "No se pudo guardar el cambio" });
      }

      return json(res, 200, { ok: true });
    }

    return json(res, 400, { error: "Acción desconocida" });
  } catch {
    return json(res, 500, { error: "Error interno del servidor" });
  }
}
