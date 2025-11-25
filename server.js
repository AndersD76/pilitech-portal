/**
 * PILI TECH - Portal Unificado
 * Servidor com autenticação para Admin e Cliente
 */

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 3000;

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'pilitech_secret_key_2025';

// Database connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL || 'postgresql://neondb_owner:npg_pCqSLW9j2hKQ@ep-crimson-heart-ahcg1r28-pooler.c-3.us-east-1.aws.neon.tech/neondb?sslmode=require',
  ssl: { rejectUnauthorized: false }
});

// Usuarios (em producao, isso estaria no banco de dados)
const USERS = {
  // Administrador
  'admin': {
    password: '@2025@2026',
    role: 'admin',
    name: 'Administrador',
    permissions: ['all']
  },
  // Clientes (podem ser adicionados mais)
  'cliente': {
    password: 'cliente123',
    role: 'cliente',
    name: 'Cliente Demo',
    serialNumbers: ['00002025']
  },
  'cargill': {
    password: 'cargill2025',
    role: 'cliente',
    name: 'Cargill',
    serialNumbers: ['00002025']
  },
  'jbs': {
    password: 'jbs2025',
    role: 'cliente',
    name: 'JBS',
    serialNumbers: ['00002025']
  }
};

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Middleware de autenticacao
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Token nao fornecido' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Token invalido' });
    }
    req.user = user;
    next();
  });
}

// Middleware para verificar se e admin
function requireAdmin(req, res, next) {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Acesso negado. Apenas administradores.' });
  }
  next();
}

// ============ ROTAS DE AUTENTICACAO ============

// Login
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;

  // Primeiro verifica usuários hardcoded (admin)
  const hardcodedUser = USERS[username.toLowerCase()];

  if (hardcodedUser && hardcodedUser.password === password) {
    const token = jwt.sign(
      {
        username: username.toLowerCase(),
        role: hardcodedUser.role,
        name: hardcodedUser.name,
        serialNumbers: hardcodedUser.serialNumbers || []
      },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    return res.json({
      success: true,
      token,
      user: {
        username: username.toLowerCase(),
        role: hardcodedUser.role,
        name: hardcodedUser.name
      }
    });
  }

  // Verifica clientes no banco de dados
  try {
    const result = await pool.query(
      'SELECT id, username, password, name FROM clients WHERE username = $1 AND active = true',
      [username.toLowerCase()]
    );

    if (result.rows.length > 0 && result.rows[0].password === password) {
      const dbClient = result.rows[0];

      // Buscar dispositivos associados
      const devicesResult = await pool.query(
        'SELECT serial_number FROM client_devices WHERE client_id = $1',
        [dbClient.id]
      );
      const serialNumbers = devicesResult.rows.map(r => r.serial_number);

      const token = jwt.sign(
        {
          username: dbClient.username,
          role: 'cliente',
          name: dbClient.name,
          serialNumbers: serialNumbers
        },
        JWT_SECRET,
        { expiresIn: '24h' }
      );

      return res.json({
        success: true,
        token,
        user: {
          username: dbClient.username,
          role: 'cliente',
          name: dbClient.name
        }
      });
    }
  } catch (err) {
    console.error('Erro ao verificar cliente no banco:', err);
  }

  // Nenhum usuário encontrado
  return res.status(401).json({
    success: false,
    message: 'Usuario ou senha incorretos'
  });
});

// Verificar token
app.get('/api/verify', authenticateToken, (req, res) => {
  res.json({ valid: true, user: req.user });
});

// Logout (client-side apenas remove o token)
app.post('/api/logout', (req, res) => {
  res.json({ success: true });
});

// ============ ROTAS DE DADOS ============

// Obter dispositivos (filtrado por role)
app.get('/api/devices', authenticateToken, async (req, res) => {
  try {
    let query = `
      SELECT
        d.id,
        d.serial_number,
        d.name,
        d.last_seen
      FROM devices d
    `;

    // Se for cliente, filtra pelos serial numbers permitidos
    if (req.user.role === 'cliente' && req.user.serialNumbers) {
      query += ` WHERE d.serial_number = ANY($1)`;
      const result = await pool.query(query, [req.user.serialNumbers]);
      return res.json(result.rows);
    }

    const result = await pool.query(query + ' ORDER BY d.serial_number');
    res.json(result.rows);
  } catch (err) {
    console.error('Erro ao buscar devices:', err);
    res.status(500).json({ error: err.message });
  }
});

// Obter leituras mais recentes
app.get('/api/latest-readings', authenticateToken, async (req, res) => {
  try {
    let whereClause = '';
    let params = [];

    if (req.user.role === 'cliente' && req.user.serialNumbers) {
      whereClause = 'WHERE d.serial_number = ANY($1)';
      params = [req.user.serialNumbers];
    }

    const query = `
      WITH latest AS (
        SELECT DISTINCT ON (device_id)
          device_id,
          timestamp,
          sistema_ligado,
          sensor_0_graus,
          sensor_40_graus,
          trava_roda,
          moega_cheia,
          fosso_cheio,
          subindo,
          descendo,
          ciclos_hoje,
          ciclos_total,
          horas_operacao,
          minutos_operacao,
          free_heap,
          uptime_seconds,
          wifi_connected
        FROM sensor_readings
        ORDER BY device_id, timestamp DESC
      )
      SELECT
        d.serial_number,
        d.name,
        d.last_seen,
        l.*
      FROM devices d
      LEFT JOIN latest l ON l.device_id = d.id
      ${whereClause}
      ORDER BY d.serial_number
    `;

    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (err) {
    console.error('Erro ao buscar leituras:', err);
    res.status(500).json({ error: err.message });
  }
});

// Obter estatisticas (admin only)
app.get('/api/stats', authenticateToken, async (req, res) => {
  try {
    // Total de dispositivos
    let devicesQuery = 'SELECT COUNT(*) as total FROM devices';
    let devicesParams = [];

    if (req.user.role === 'cliente' && req.user.serialNumbers) {
      devicesQuery = 'SELECT COUNT(*) as total FROM devices WHERE serial_number = ANY($1)';
      devicesParams = [req.user.serialNumbers];
    }

    const devicesResult = await pool.query(devicesQuery, devicesParams);

    // Dispositivos online (ultima leitura < 10 min e wifi_connected = true)
    let onlineQuery = `
      SELECT COUNT(DISTINCT d.id) as online
      FROM devices d
      JOIN sensor_readings sr ON sr.device_id = d.id
      WHERE sr.timestamp > NOW() - INTERVAL '10 minutes'
        AND sr.wifi_connected = true
    `;
    let onlineParams = [];

    if (req.user.role === 'cliente' && req.user.serialNumbers) {
      onlineQuery += ' AND d.serial_number = ANY($1)';
      onlineParams = [req.user.serialNumbers];
    }

    const onlineResult = await pool.query(onlineQuery, onlineParams);

    // Total de ciclos
    let ciclosQuery = `
      SELECT COALESCE(SUM(ciclos_total), 0) as total_ciclos
      FROM (
        SELECT DISTINCT ON (device_id) ciclos_total
        FROM sensor_readings
        ORDER BY device_id, timestamp DESC
      ) latest
    `;

    const ciclosResult = await pool.query(ciclosQuery);

    // Total de leituras
    let leiturasQuery = 'SELECT COUNT(*) as total FROM sensor_readings';
    const leiturasResult = await pool.query(leiturasQuery);

    // Alertas recentes (24h)
    let alertasQuery = `
      SELECT COUNT(*) as total
      FROM event_logs
      WHERE event_type = 'ALERT'
        AND timestamp > NOW() - INTERVAL '24 hours'
    `;
    const alertasResult = await pool.query(alertasQuery);

    res.json({
      totalDevices: parseInt(devicesResult.rows[0].total),
      onlineDevices: parseInt(onlineResult.rows[0].online),
      totalCiclos: parseInt(ciclosResult.rows[0].total_ciclos),
      totalLeituras: parseInt(leiturasResult.rows[0].total),
      alertas24h: parseInt(alertasResult.rows[0].total)
    });
  } catch (err) {
    console.error('Erro ao buscar stats:', err);
    res.status(500).json({ error: err.message });
  }
});

// Obter alertas recentes
app.get('/api/recent-alerts', authenticateToken, async (req, res) => {
  try {
    let whereClause = '';
    let params = [];

    if (req.user.role === 'cliente' && req.user.serialNumbers) {
      whereClause = 'AND d.serial_number = ANY($1)';
      params = [req.user.serialNumbers];
    }

    const query = `
      SELECT
        e.id,
        e.timestamp,
        e.event_type,
        e.message,
        e.sensor_name,
        e.sensor_value,
        d.serial_number,
        d.name as device_name
      FROM event_logs e
      JOIN devices d ON e.device_id = d.id
      WHERE e.timestamp > NOW() - INTERVAL '24 hours'
      ${whereClause}
      ORDER BY e.timestamp DESC
      LIMIT 50
    `;

    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (err) {
    console.error('Erro ao buscar alertas:', err);
    res.status(500).json({ error: err.message });
  }
});

// Obter manutencoes
app.get('/api/maintenance', authenticateToken, async (req, res) => {
  try {
    let whereClause = '';
    let params = [];

    if (req.user.role === 'cliente' && req.user.serialNumbers) {
      whereClause = 'WHERE d.serial_number = ANY($1)';
      params = [req.user.serialNumbers];
    }

    const query = `
      SELECT
        m.id,
        m.timestamp,
        m.technician,
        m.description,
        m.horas_operacao,
        d.serial_number,
        d.name as device_name
      FROM maintenance_logs m
      JOIN devices d ON m.device_id = d.id
      ${whereClause}
      ORDER BY m.timestamp DESC
      LIMIT 50
    `;

    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (err) {
    console.error('Erro ao buscar manutencoes:', err);
    res.status(500).json({ error: err.message });
  }
});

// ============ CRUD DE CLIENTES (admin only) ============

// Listar todos os clientes
app.get('/api/clients', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const query = `
      SELECT
        c.id,
        c.username,
        c.name,
        c.email,
        c.phone,
        c.created_at,
        c.active,
        COALESCE(
          (SELECT array_agg(cd.serial_number) FROM client_devices cd WHERE cd.client_id = c.id),
          ARRAY[]::varchar[]
        ) as serial_numbers
      FROM clients c
      ORDER BY c.name
    `;
    const result = await pool.query(query);
    res.json(result.rows);
  } catch (err) {
    console.error('Erro ao buscar clientes:', err);
    res.status(500).json({ error: err.message });
  }
});

// Obter um cliente específico
app.get('/api/clients/:id', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const query = `
      SELECT
        c.id,
        c.username,
        c.name,
        c.email,
        c.phone,
        c.created_at,
        c.active,
        COALESCE(
          (SELECT array_agg(cd.serial_number) FROM client_devices cd WHERE cd.client_id = c.id),
          ARRAY[]::varchar[]
        ) as serial_numbers
      FROM clients c
      WHERE c.id = $1
    `;
    const result = await pool.query(query, [id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Cliente não encontrado' });
    }
    res.json(result.rows[0]);
  } catch (err) {
    console.error('Erro ao buscar cliente:', err);
    res.status(500).json({ error: err.message });
  }
});

// Criar novo cliente
app.post('/api/clients', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { username, password, name, email, phone, serialNumbers } = req.body;

    // Validação
    if (!username || !password || !name) {
      return res.status(400).json({ error: 'Username, password e name são obrigatórios' });
    }

    // Verificar se username já existe
    const existing = await pool.query('SELECT id FROM clients WHERE username = $1', [username.toLowerCase()]);
    if (existing.rows.length > 0) {
      return res.status(400).json({ error: 'Username já existe' });
    }

    // Inserir cliente
    const insertResult = await pool.query(
      `INSERT INTO clients (username, password, name, email, phone)
       VALUES ($1, $2, $3, $4, $5) RETURNING id`,
      [username.toLowerCase(), password, name, email || null, phone || null]
    );

    const clientId = insertResult.rows[0].id;

    // Associar dispositivos se fornecidos
    if (serialNumbers && serialNumbers.length > 0) {
      for (const sn of serialNumbers) {
        await pool.query(
          'INSERT INTO client_devices (client_id, serial_number) VALUES ($1, $2) ON CONFLICT DO NOTHING',
          [clientId, sn]
        );
      }
    }

    res.status(201).json({ success: true, id: clientId, message: 'Cliente criado com sucesso' });
  } catch (err) {
    console.error('Erro ao criar cliente:', err);
    res.status(500).json({ error: err.message });
  }
});

// Atualizar cliente
app.put('/api/clients/:id', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { username, password, name, email, phone, active, serialNumbers } = req.body;

    // Verificar se cliente existe
    const existing = await pool.query('SELECT id FROM clients WHERE id = $1', [id]);
    if (existing.rows.length === 0) {
      return res.status(404).json({ error: 'Cliente não encontrado' });
    }

    // Atualizar campos (senha opcional)
    if (password) {
      await pool.query(
        `UPDATE clients SET username = $1, password = $2, name = $3, email = $4, phone = $5, active = $6 WHERE id = $7`,
        [username.toLowerCase(), password, name, email || null, phone || null, active !== false, id]
      );
    } else {
      await pool.query(
        `UPDATE clients SET username = $1, name = $2, email = $3, phone = $4, active = $5 WHERE id = $6`,
        [username.toLowerCase(), name, email || null, phone || null, active !== false, id]
      );
    }

    // Atualizar dispositivos associados
    if (serialNumbers !== undefined) {
      // Remover associações antigas
      await pool.query('DELETE FROM client_devices WHERE client_id = $1', [id]);

      // Adicionar novas associações
      if (serialNumbers && serialNumbers.length > 0) {
        for (const sn of serialNumbers) {
          await pool.query(
            'INSERT INTO client_devices (client_id, serial_number) VALUES ($1, $2) ON CONFLICT DO NOTHING',
            [id, sn]
          );
        }
      }
    }

    res.json({ success: true, message: 'Cliente atualizado com sucesso' });
  } catch (err) {
    console.error('Erro ao atualizar cliente:', err);
    res.status(500).json({ error: err.message });
  }
});

// Excluir cliente
app.delete('/api/clients/:id', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;

    const result = await pool.query('DELETE FROM clients WHERE id = $1 RETURNING id', [id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Cliente não encontrado' });
    }

    res.json({ success: true, message: 'Cliente excluído com sucesso' });
  } catch (err) {
    console.error('Erro ao excluir cliente:', err);
    res.status(500).json({ error: err.message });
  }
});

// Listar dispositivos disponíveis para associar
app.get('/api/available-devices', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query('SELECT serial_number, name FROM devices ORDER BY serial_number');
    res.json(result.rows);
  } catch (err) {
    console.error('Erro ao buscar dispositivos:', err);
    res.status(500).json({ error: err.message });
  }
});

// ============ ROTAS DE PAGINAS ============

// Pagina admin (protegida)
app.get('/admin.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// Pagina cliente (protegida)
app.get('/cliente.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'cliente.html'));
});

// Rota padrao - redireciona para index
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ============ START SERVER ============

app.listen(PORT, () => {
  console.log('');
  console.log('=========================================');
  console.log('   PILI TECH - Portal Unificado');
  console.log('=========================================');
  console.log('');
  console.log(`   URL: http://localhost:${PORT}`);
  console.log('');
  console.log('   Credenciais Admin:');
  console.log('   Usuario: admin');
  console.log('   Senha: @2025@2026');
  console.log('');
  console.log('   Credenciais Cliente Demo:');
  console.log('   Usuario: cliente');
  console.log('   Senha: cliente123');
  console.log('');
  console.log('=========================================');
});
