const express = require('express');
const mysql = require('mysql2/promise'); // Cambiado a `mysql2/promise` para usar pool con promesas
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const cors = require('cors'); 
const app = express();
const port = 3000;
const bcrypt = require('bcryptjs');
require('dotenv').config();

const allowedOrigins = [
  'http://localhost:8100',
  'http://backendplaytab-production.up.railway.app',
  'https://localhost',
  'http://localhost:8101'
];

app.use(cors({
  origin: (origin, callback) => {
    console.log('Request origin:', origin);
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true); // Permitir el origen
    } else {
      callback(new Error('CORS no permitido')); // Bloquear origen no autorizado
    }
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE'], // Métodos permitidos
  allowedHeaders: ['Content-Type', 'Authorization'], // Encabezados permitidos
  credentials: true // Permitir cookies y autenticación
}));
app.options('*', cors()); // Maneja solicitudes preflight para cualquier ruta
app.use(express.json());

// Configuración de la base de datos con pool
const pool = mysql.createPool({
  host: process.env.EV_HOST,
  user: process.env.EV_USERNAME,
  password: process.env.EV_PASS, 
  database: process.env.EV_NAME,
  waitForConnections: true,
  connectionLimit: 10, // Límite de conexiones en el pool
  queueLimit: 0       // No limitar las solicitudes en cola
});

// Verificar conexión al iniciar el servidor
(async () => {
  try {
    const connection = await pool.getConnection();
    console.log('Conexión exitosa al pool de base de datos');
    connection.release(); // Liberar la conexión inmediatamente
  } catch (err) {
    console.error('Error al conectar con el pool de base de datos:', err);
  }
})();

// Ruta para recuperación de contraseña usando el pool
app.post('/recover-password', async (req, res) => {
  const { RUT, correo } = req.body;

  if (!RUT || !correo) {
    return res.status(400).json({ error: 'RUT y correo son requeridos' });
  }

  try {
    const connection = await pool.getConnection(); // Obtener conexión del pool

    // Verificar si el usuario existe
    const query = 'SELECT * FROM USUARIO WHERE Run_User = ? AND Correo_User = ?';
    const [results] = await connection.query(query, [RUT, correo]);

    if (results.length === 0) {
      connection.release(); // Liberar la conexión
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }

    // Generar un token de recuperación
    const token = crypto.randomBytes(20).toString('hex');

    // Actualizar el token en la base de datos
    const updateTokenQuery = 'UPDATE USUARIO SET token = ? WHERE Run_User = ?';
    await connection.query(updateTokenQuery, [token, RUT]);

    connection.release(); // Liberar la conexión

    // Configurar y enviar el correo
    const transporter = nodemailer.createTransport({
      service: 'Gmail',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
      }
    });

    const resetUrl = `${token}`;

    const mailOptions = {
      from: 'playtab.app2024@gmail.com',
      to: correo,
      subject: 'Recuperación de contraseña',
      html: `
        <div style="font-family: Arial, sans-serif; text-align: center; padding: 20px; background-color: #f4f4f9; color: #333;">
          <div style="max-width: 600px; margin: 0 auto; background-color: #ffffff; border: 1px solid #ddd; border-radius: 5px; overflow: hidden;">
            <div style="background-color: #ff9800; padding: 10px 20px;">
              <h2 style="color: #ffffff; margin: 0;">Recuperación de Contraseña</h2>
            </div>
            <div style="padding: 20px; text-align: left;">
              <p>Hola,</p>
              <p>Has solicitado restablecer tu contraseña. Usa el siguiente código para continuar:</p>
              <div style="margin: 20px 0; padding: 10px; background-color: #f7f7f7; border: 1px dashed #ddd; text-align: center; font-size: 20px; font-weight: bold; color: #333;">
                ${resetUrl}
              </div>
              <p>Si no realizaste esta solicitud, puedes ignorar este mensaje.</p>
              <p style="margin: 20px 0 0;">Gracias,</p>
              <p><strong>El equipo de PlayTab</strong></p>
            </div>
            <div style="background-color: #f4f4f9; padding: 10px; font-size: 12px; color: #666;">
              <p>Este correo se generó automáticamente, por favor no respondas.</p>
            </div>
          </div>
        </div>
      `
    };

    transporter.sendMail(mailOptions, (error) => {
      if (error) {
        console.error('Error enviando el correo:', error);
        return res.status(500).json({ error: 'Error enviando el correo' });
      }
      res.status(200).json({ message: 'Código de recuperación enviado' });
    });
  } catch (error) {
    console.error('Error en recuperación de contraseña:', error);
    res.status(500).json({ error: 'Error en el servidor' });
  }
});
app.post('/reset-password', async (req, res) => {
  const { token, newPassword } = req.body;

  if (!token || !newPassword) {
    return res.status(400).json({ error: 'Token y nueva contraseña son requeridos' });
  }

  try {
    const connection = await pool.getConnection(); // Obtener una conexión del pool

    // Verificar si el token es válido
    const query = 'SELECT * FROM USUARIO WHERE token = ?';
    const [results] = await connection.query(query, [token]);

    if (results.length === 0) {
      connection.release(); // Liberar la conexión
      return res.status(404).json({ error: 'Token inválido o expirado' });
    }

    // Encriptar la nueva contraseña
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Actualizar la contraseña y eliminar el token
    const updatePasswordQuery = 'UPDATE USUARIO SET Contra_User = ?, token = NULL WHERE token = ?';
    await connection.query(updatePasswordQuery, [hashedPassword, token]);

    connection.release(); // Liberar la conexión

    res.status(200).json({ message: 'Contraseña actualizada exitosamente' });
  } catch (error) {
    console.error('Error al restablecer la contraseña:', error);
    res.status(500).json({ error: 'Error en el servidor' });
  }
});

// HASTA AQUÍ EL TEMA DE RECUPERAR CONTRASEÑA ******************************************

app.get('/api/maps-key', (req, res) => {
  try {
    const apiKey = process.env.EV_MAPS; 
    if (!apiKey) {
      return res.status(404).json({ error: 'API Key no encontrada' });
    }
    res.status(200).json({ apiKey });
  } catch (error) {
    console.error('Error al obtener la API Key:', error);
    res.status(500).json({ error: 'Error al obtener la API Key' });
  }
});


// 1. Aquí se obtendrá las Regiones y Comunas disponibles para poder registrar al usuario.
app.get('/regiones', (req, res) => {
  const query = 'SELECT * FROM REGION';

  pool.query(query, (err, results) => {
    if (err) {
      console.error('Error al obtener las regiones:', err);
      return res.status(500).json({ error: 'Error al obtener las regiones' });
    }

    res.status(200).json(results);
  });
});


// Obtener las comunas por id de la región.
app.get('/comunas/:regionId', (req, res) => {
  const { regionId } = req.params; 
  const query = 'SELECT * FROM COMUNA WHERE Id_Region = ?';

  pool.query(query, [regionId], (err, results) => {
    if (err) {
      console.error('Error al obtener las comunas:', err);
      return res.status(500).json({ error: 'Error al obtener las comunas' });
    }

    if (results.length === 0) {
      return res.status(404).json({ message: 'No se encontraron comunas para esta región' });
    }

    res.status(200).json(results);
  });
});


// 2. Aquí se realizará el INSERT del usuario. 
app.post('/register', async (req, res) => {
  const { Run_User, Nom_User, Correo_User, Contra_User, Celular_User, FechaNac_User, Id_Comuna } = req.body;

  // Verificación de datos requeridos
  if (!Run_User || !Nom_User || !Correo_User || !Contra_User || !Celular_User || !FechaNac_User || !Id_Comuna) {
    return res.status(400).json({ error: 'Faltan datos requeridos' });
  }

  try {
    // Encriptar contraseña
    const hashedPassword = await bcrypt.hash(Contra_User, 10);

    // Consulta SQL
    const query = `
      INSERT INTO USUARIO 
      (Run_User, Tipo_User, Nom_User, Correo_User, Contra_User, Celular_User, FechaNac_User, FechaCreacion_User, Id_Comuna, Id_Estado) 
      VALUES (?, 101, ?, ?, ?, ?, ?, NOW(), ?, 15)
    `;

    // Ejecutar la consulta
    pool.query(
      query, 
      [Run_User, Nom_User, Correo_User, hashedPassword, Celular_User, FechaNac_User, Id_Comuna], 
      (err, result) => {
        if (err) {
          console.error('Error al registrar el usuario:', err);

          // Manejo de errores específicos
          if (err.code === 'ER_DUP_ENTRY') {
            return res.status(409).json({ error: 'El usuario ya existe' });
          }

          return res.status(500).json({ error: 'Error al registrar el usuario' });
        }

        // Respuesta exitosa
        res.status(201).json({ message: 'Usuario registrado exitosamente' });
      }
    );
  } catch (error) {
    console.error('Error al procesar la solicitud:', error);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// 2. Aquí se realizará el INSERT de la actividad. 
app.post('/actividad', (req, res) => {
  const {
    Nom_Actividad,
    Desc_Actividad,
    Direccion_Actividad,
    Id_MaxJugador,
    Fecha_INI_Actividad,
    Fecha_TER_Actividad,
    Id_Comuna,
    Id_SubCategoria,
    Id_Estado,
    Id_Anfitrion_Actividad,
    Celular_User,
  } = req.body;

  // Validación de los datos requeridos
  if (
    !Nom_Actividad || !Desc_Actividad || !Direccion_Actividad || !Id_MaxJugador || 
    !Fecha_INI_Actividad || !Fecha_TER_Actividad || !Id_Comuna || 
    !Id_SubCategoria || !Id_Estado || !Id_Anfitrion_Actividad || !Celular_User
  ) {
    return res.status(400).json({ error: 'Faltan datos requeridos' });
  }

  // Consulta SQL para insertar la actividad
  const query = `
    INSERT INTO ACTIVIDAD 
    (Nom_Actividad, Desc_Actividad, Direccion_Actividad, Id_MaxJugador, Fecha_INI_Actividad, Fecha_TER_Actividad, Id_Comuna, Id_SubCategoria, Id_Estado, Id_Anfitrion_Actividad, Celular_User) 
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `;

  // Ejecutar la consulta
  pool.query(
    query, 
    [
      Nom_Actividad,
      Desc_Actividad,
      Direccion_Actividad,
      Id_MaxJugador,
      Fecha_INI_Actividad,
      Fecha_TER_Actividad,
      Id_Comuna,
      Id_SubCategoria,
      Id_Estado,
      Id_Anfitrion_Actividad,
      Celular_User,
    ], 
    (err, result) => {
      if (err) {
        console.error('Error al registrar la actividad:', err);

        // Manejo de errores específicos
        if (err.code === 'ER_DUP_ENTRY') {
          return res.status(409).json({ error: 'La actividad ya existe' });
        }

        return res.status(500).json({ error: 'Error al registrar la actividad' });
      }

      // Respuesta exitosa
      res.status(201).json({ message: 'Actividad registrada exitosamente', id: result.insertId });
    }
  );
});


// Ruta para el login del usuario (Obtener los datos de la consulta)
app.post('/login', (req, res) => {
  const { Correo_User, Contra_User } = req.body;

  // Validar datos requeridos
  if (!Correo_User || !Contra_User) {
    return res.status(400).json({ error: 'Correo y contraseña son requeridos' });
  }

  // Consulta SQL para obtener datos del usuario
  const query = `
  SELECT 
    USUARIO.Id_User, USUARIO.Tipo_User, USUARIO.Nom_User, USUARIO.Correo_User, USUARIO.Celular_User, 
    USUARIO.Contra_User, COMUNA.Id_Comuna, COMUNA.Nombre_Comuna, 
    REGION.Id_Region, REGION.Nombre_Region, SUBCATEGORIA.Id_SubCategoria, SUBCATEGORIA.Nom_SubCategoria
  FROM USUARIO 
  INNER JOIN COMUNA ON USUARIO.Id_Comuna = COMUNA.Id_Comuna 
  INNER JOIN REGION ON COMUNA.Id_Region = REGION.Id_Region
  LEFT JOIN FAVORITO ON USUARIO.Id_User = FAVORITO.Id_User
  LEFT JOIN SUBCATEGORIA ON FAVORITO.Id_SubCategoria = SUBCATEGORIA.Id_SubCategoria
  WHERE Correo_User = ?`;

  // Ejecutar consulta con `pool`
  pool.query(query, [Correo_User], async (err, result) => {
    if (err) {
      console.error('Error durante el login:', err);
      return res.status(500).json({ error: 'Error en el servidor' });
    }

    // Validar si el usuario existe
    if (result.length === 0) {
      return res.status(401).json({ error: 'Credenciales inválidas' });
    }

    const user = result[0];

    try {
      // Verificar la contraseña con bcrypt
      const isPasswordValid = await bcrypt.compare(Contra_User, user.Contra_User);

      if (!isPasswordValid) {
        return res.status(401).json({ error: 'Credenciales inválidas' });
      }

      // Eliminar contraseña de la respuesta
      delete user.Contra_User;

      // Responder con éxito
      res.status(200).json({ message: 'Login exitoso', user });
    } catch (error) {
      console.error('Error al comparar contraseñas:', error);
      res.status(500).json({ error: 'Error en el servidor' });
    }
  });
});

// 3. Aquí se obtendrá las Categoria y subcategoria 
app.get('/categoria', (req, res) => {
  const query = 'SELECT * FROM CATEGORIA';

  // Ejecutar consulta con `pool`
  pool.query(query, (err, results) => {
    if (err) {
      console.error('Error al obtener categorías:', err);
      return res.status(500).json({ error: 'Error en el servidor al obtener las categorías' });
    }

    // Responder con los resultados
    res.status(200).json(results);
  });
});

app.get('/subcategoria/:categoriaId', (req, res) => {
  const categoriaId = req.params.categoriaId;
  const query = 'SELECT * FROM SUBCATEGORIA WHERE Id_Categoria = ?';

  // Ejecutar consulta con `pool`
  pool.query(query, [categoriaId], (err, results) => {
    if (err) {
      console.error('Error al obtener subcategorías:', err);
      return res.status(500).json({ error: 'Error en el servidor al obtener las subcategorías' });
    }

    // Responder con los resultados
    res.status(200).json(results);
  });
});


// 4. Aquí se obtendrá los jugadores máximos
app.get('/cantidad', (req, res) => {
  const query = 'SELECT * FROM MAXJUGADOR';

  // Ejecutar consulta con `pool`
  pool.query(query, (err, results) => {
    if (err) {
      console.error('Error al obtener datos de MAXJUGADOR:', err);
      return res.status(500).json({ error: 'Error en el servidor al obtener datos de MAXJUGADOR' });
    }

    // Responder con los resultados
    res.status(200).json(results);
  });
});


// 5. Este es para obtener las actividades
app.get('/actividades', (req, res) => {
  const { Id_Comuna } = req.query;

  if (!Id_Comuna) {
    return res.status(400).json({ error: 'El parámetro Id_Comuna es requerido' });
  }

  const query = `
    SELECT 
      a.Id_Actividad, 
      u.Nom_User, 
      a.Nom_Actividad, 
      a.Fecha_INI_Actividad, 
      DATE_FORMAT(a.Fecha_INI_Actividad, '%d/%m/%Y') AS Fecha_Inicio, 
      DATE_FORMAT(a.Fecha_INI_Actividad, '%H:%i') AS Hora_Inicio,
      a.Fecha_TER_Actividad, 
      DATE_FORMAT(a.Fecha_TER_Actividad, '%d/%m/%Y') AS Fecha_Termino, 
      DATE_FORMAT(a.Fecha_TER_Actividad, '%H:%i') AS Hora_Termino,
      a.Desc_Actividad, 
      a.Direccion_Actividad, 
      m.Cantidad_MaxJugador, 
      s.Nom_SubCategoria, 
      C.Nom_Categoria, 
      i.Url 
    FROM ACTIVIDAD a 
    INNER JOIN USUARIO u ON a.Id_Anfitrion_Actividad = u.Id_User 
    INNER JOIN MAXJUGADOR m ON a.Id_Maxjugador = m.Id_Maxjugador 
    INNER JOIN SUBCATEGORIA s ON s.Id_SubCategoria = a.Id_SubCategoria 
    INNER JOIN CATEGORIA C ON s.Id_Categoria = C.Id_Categoria 
    LEFT JOIN IMAGEN i ON s.Id_SubCategoria = i.Id_SubCategoria
    WHERE a.Id_Comuna = ? 
      AND Fecha_INI_Actividad <= NOW() 
      AND Fecha_TER_Actividad >= NOW();
  `;

  // Ejecutar la consulta con `pool`
  pool.query(query, [Id_Comuna], (err, results) => {
    if (err) {
      console.error('Error al obtener actividades:', err);
      return res.status(500).json({ error: 'Error al obtener actividades' });
    }

    // Responder con los resultados
    res.status(200).json(results);
  });
});


app.get('/jugdoresInscritos', (req, res) => {
  const { Id_Actividad } = req.query;

  if (!Id_Actividad) {
    return res.status(400).json({ error: 'El parámetro Id_Actividad es requerido' });
  }

  const query = 'SELECT COUNT(*) AS jugadoresInscritos FROM PARTICIPANTE WHERE Id_Actividad = ?';

  // Ejecutar la consulta con `pool`
  pool.query(query, [Id_Actividad], (err, results) => {
    if (err) {
      console.error('Error al obtener jugadores inscritos:', err);
      return res.status(500).json({ error: 'Error al obtener los jugadores inscritos' });
    }

    // Responder con los resultados en formato claro
    res.status(200).json({ jugadoresInscritos: results[0].jugadoresInscritos });
  });
});

// insertar participante en la Actividad
app.post('/participante', (req, res) => {
  const { Id_Actividad, Id_Asistencia, Id_User, Tipo_Participante } = req.body;

  // Validación de los datos requeridos
  if (!Id_Actividad || !Id_User) {
    return res.status(400).json({ error: 'Faltan datos requeridos: Id_Actividad e Id_User son obligatorios.' });
  }

  const query = `
    INSERT INTO PARTICIPANTE (Id_Actividad, Id_Asistencia, Id_User, Tipo_Participante) 
    VALUES (?, ?, ?, ?)
  `;

  // Ejecutar la consulta con `pool`
  pool.query(
    query,
    [Id_Actividad, Id_Asistencia || 800, Id_User, Tipo_Participante || null],
    (err, result) => {
      if (err) {
        console.error('Error al insertar participante:', err);
        return res.status(500).json({ error: 'Error al insertar participante' });
      }

      res.status(201).json({ message: 'Participante registrado exitosamente', id: result.insertId });
    }
  );
});


//Eliminar Usuario
app.delete('/borrarUser/:Id_User', (req, res) => {
  const Id_User = req.params.Id_User;

  // Validación para asegurar que se proporciona un Id_User
  if (!Id_User) {
    return res.status(400).json({ error: 'Id_User es requerido' });
  }

  const deleteQuery = 'DELETE FROM USUARIO WHERE Id_User = ?';

  // Ejecutar la consulta con `pool`
  pool.query(deleteQuery, [Id_User], (err, result) => {
    if (err) {
      console.error('Error al eliminar el usuario:', err);
      return res.status(500).json({ error: 'Error al eliminar el usuario' });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }

    res.status(200).json({ message: 'Usuario eliminado con éxito' });
  });
});

// Cambiar la comuna
app.put('/cambiaComuna', (req, res) => {
  const { Id_Comuna, Id_User } = req.body;

  // Validación de parámetros
  if (!Id_Comuna || !Id_User) {
    return res.status(400).json({ error: 'Faltan datos requeridos: Id_Comuna y Id_User son necesarios' });
  }

  const query = `
    UPDATE USUARIO 
    SET Id_Comuna = ? 
    WHERE Id_User = ?;
  `;

  // Ejecutar la consulta con `pool`
  pool.query(query, [Id_Comuna, Id_User], (err, result) => {
    if (err) {
      console.error('Error al actualizar la comuna:', err);
      return res.status(500).json({ error: 'Error al actualizar la comuna' });
    }

    // Verificar si el usuario fue encontrado y actualizado
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }

    res.status(200).json({ message: 'Comuna actualizada exitosamente' });
  });
});


//Ver el historial de actividades
app.get('/historial', (req, res) => {
  const { Id_User } = req.query;

  // Validación de parámetros
  if (!Id_User) {
    return res.status(400).json({ error: 'El parámetro Id_User es requerido' });
  }

  const query = `
    SELECT DISTINCT 
      u.Nom_User, 
      a.Nom_Actividad, 
      a.Desc_Actividad, 
      a.Direccion_Actividad, 
      a.Celular_User, 
      a.Fecha_TER_Actividad, 
      s.Nom_SubCategoria, 
      i.url
    FROM PARTICIPANTE p
    JOIN ACTIVIDAD a ON p.Id_Actividad = a.Id_Actividad
    JOIN USUARIO u ON a.Id_Anfitrion_Actividad = u.Id_User
    LEFT JOIN SUBCATEGORIA s ON s.Id_SubCategoria = a.Id_SubCategoria
    LEFT JOIN IMAGEN i ON a.Id_SubCategoria = i.Id_SubCategoria
    WHERE p.Id_User = ?
    ORDER BY a.Fecha_TER_Actividad DESC;
  `;

  // Ejecutar la consulta con `pool`
  pool.query(query, [Id_User], (err, results) => {
    if (err) {
      console.error('Error al obtener el historial:', err);
      return res.status(500).json({ error: 'Error al obtener el historial' });
    }

    // Comprobar si hay resultados
    if (results.length === 0) {
      return res.status(404).json({ message: 'No se encontró historial para el usuario especificado' });
    }

    // Respuesta exitosa
    res.status(200).json(results);
  });
});


// Obtener actividades y datos especificos de la actividad de los usuarios inscritos
app.get('/actividad_activa', (req, res) => {
  const { Id_User } = req.query;

  // Validación de parámetros
  if (!Id_User) {
    return res.status(400).json({ error: 'El parámetro Id_User es requerido' });
  }

  const query = `
    SELECT DISTINCT 
      a.Nom_Actividad, 
      a.Id_Actividad, 
      u.Nom_User, 
      a.Desc_Actividad, 
      u.Celular_User, 
      a.Direccion_Actividad, 
      m.Cantidad_MaxJugador, 
      a.Fecha_TER_Actividad, 
      DATE_FORMAT(a.Fecha_TER_Actividad, '%d/%m/%Y') AS Fecha_Termino, 
      DATE_FORMAT(a.Fecha_TER_Actividad, '%H:%i') AS Hora_Termino,
      p.Tipo_Participante, 
      s.Nom_SubCategoria, 
      i.Url
    FROM PARTICIPANTE p
    JOIN ACTIVIDAD a ON p.Id_Actividad = a.Id_Actividad
    INNER JOIN MAXJUGADOR m ON a.Id_Maxjugador = m.Id_Maxjugador
    JOIN USUARIO u ON a.Id_Anfitrion_Actividad = u.Id_User
    LEFT JOIN SUBCATEGORIA s ON s.Id_SubCategoria = a.Id_SubCategoria
    LEFT JOIN IMAGEN i ON a.Id_SubCategoria = i.Id_SubCategoria
    WHERE 
      p.Id_User = ? 
      AND p.Tipo_Participante = 200 
      AND Fecha_INI_Actividad <= NOW() 
      AND Fecha_TER_Actividad >= NOW();
  `;

  // Ejecutar la consulta con `pool`
  pool.query(query, [Id_User], (err, results) => {
    if (err) {
      console.error('Error al obtener actividades activas:', err);
      return res.status(500).json({ error: 'Error al obtener actividades activas' });
    }

    // Verificar si hay actividades activas
    if (results.length === 0) {
      return res.status(404).json({ message: 'No se encontraron actividades activas para este usuario' });
    }

    // Respuesta exitosa
    res.status(200).json(results);
  });
});


// Eliminar usuario de actividad
app.delete('/eliminar_usuario_actividad', (req, res) => {
  const { Id_User, Id_Actividad } = req.query;

  // Validación de parámetros
  if (!Id_User || !Id_Actividad) {
    return res.status(400).json({ error: 'Los parámetros Id_User e Id_Actividad son requeridos' });
  }

  const query = 'DELETE FROM PARTICIPANTE WHERE Id_User = ? AND Id_Actividad = ?';

  // Ejecutar la consulta usando `pool`
  pool.query(query, [Id_User, Id_Actividad], (err, result) => {
    if (err) {
      console.error('Error al eliminar usuario de actividad:', err);
      return res.status(500).json({ error: 'Error al eliminar usuario de la actividad' });
    }

    // Verificar si se eliminó algún registro
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'No se encontró el usuario o la actividad especificada' });
    }

    // Respuesta exitosa
    res.status(200).json({ message: 'Usuario eliminado de la actividad exitosamente' });
  });
});


app.get('/actividadesAnfitrion', (req, res) => {
  const { Id_User } = req.query;

  // Validación de parámetro
  if (!Id_User) {
    return res.status(400).json({ error: 'El parámetro Id_User es requerido' });
  }

  const query = `
      SELECT 
        a.Id_Actividad, 
        a.Nom_Actividad, 
        a.Desc_Actividad, 
        a.Direccion_Actividad, 
        m.Cantidad_MaxJugador, 
        u.Nom_User, 
        a.Fecha_INI_Actividad, 
        DATE_FORMAT(a.Fecha_INI_Actividad, '%d/%m/%Y') AS Fecha_Inicio, 
        DATE_FORMAT(a.Fecha_INI_Actividad, '%H:%i') AS Hora_Inicio,
        a.Fecha_TER_Actividad, 
        DATE_FORMAT(a.Fecha_TER_Actividad, '%d/%m/%Y') AS Fecha_Termino, 
        DATE_FORMAT(a.Fecha_TER_Actividad, '%H:%i') AS Hora_Termino,
        i.Url, 
        s.Id_SubCategoria, 
        s.Id_Categoria, 
        s.Nom_SubCategoria
      FROM ACTIVIDAD a
      INNER JOIN USUARIO u ON a.Id_Anfitrion_Actividad = u.Id_User
      JOIN IMAGEN i ON a.Id_SubCategoria = i.Id_SubCategoria
      JOIN SUBCATEGORIA s ON a.Id_SubCategoria = s.Id_SubCategoria
      JOIN CATEGORIA c ON s.Id_Categoria = c.Id_Categoria
      JOIN MAXJUGADOR m ON a.Id_MaxJugador = m.Id_MaxJugador
      WHERE a.Id_Anfitrion_Actividad = ? AND DATE(a.Fecha_INI_Actividad) = CURDATE()
      ORDER BY a.Fecha_TER_Actividad ASC;
  `;

  // Ejecutar consulta con `pool`
  pool.query(query, [Id_User], (err, results) => {
    if (err) {
      console.error('Error al obtener actividades de anfitrión:', err);
      return res.status(500).json({ error: 'Error al obtener actividades del anfitrión' });
    }

    // Verificar si se encontraron resultados
    if (results.length === 0) {
      return res.status(404).json({ error: 'No se encontraron actividades para este anfitrión' });
    }

    // Responder con los resultados
    res.status(200).json(results);
  });
});


// Actualizar actividad
app.put('/updateActividad/:id', (req, res) => {
  const Id_Actividad = req.params.id;
  const { Desc_Actividad, Direccion_Actividad, Id_MaxJugador } = req.body;

  // Validar que todos los datos requeridos estén presentes
  if (!Desc_Actividad || !Direccion_Actividad || !Id_MaxJugador) {
    return res.status(400).json({ error: 'Faltan datos requeridos para actualizar la actividad' });
  }

  const query = `
    UPDATE ACTIVIDAD 
    SET Desc_Actividad = ?, Direccion_Actividad = ?, Id_MaxJugador = ?
    WHERE Id_Actividad = ?
  `;

  // Ejecutar consulta con pool
  pool.query(query, [Desc_Actividad, Direccion_Actividad, Id_MaxJugador, Id_Actividad], (err, result) => {
    if (err) {
      console.error('Error al actualizar actividad:', err);
      return res.status(500).json({ error: 'Error al actualizar la actividad' });
    }

    // Verificar si se encontró y actualizó la actividad
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Actividad no encontrada' });
    }

    res.status(200).json({ message: 'Actividad actualizada exitosamente' });
  });
});


// Eliminar la actividad.
app.delete('/actividad/:id', (req, res) => {
  const Id_Actividad = req.params.id;

  if (!Id_Actividad) {
    return res.status(400).json({ error: 'Id de la actividad es requerido' });
  }

  const query = 'DELETE FROM ACTIVIDAD WHERE Id_Actividad = ?';

  // Ejecutar consulta con pool
  pool.query(query, [Id_Actividad], (err, result) => {
    if (err) {
      console.error('Error al eliminar actividad:', err);
      return res.status(500).json({ error: 'Error al eliminar la actividad' });
    }

    // Verificar si se eliminó alguna actividad
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'La actividad no existe' });
    }

    res.status(200).json({ message: 'Actividad eliminada exitosamente' });
  });
});


app.get('/usuarios-inscritos/:idActividad', (req, res) => {
  const { idActividad } = req.params;

  if (!idActividad) {
    return res.status(400).json({ error: 'El id de la actividad es requerido' });
  }

  const query = `
    SELECT DISTINCT u.Id_User, u.Nom_User, u.Celular_User, a.Tipo_Asistencia 
    FROM PARTICIPANTE p
    INNER JOIN USUARIO u ON p.Id_User = u.Id_User
    LEFT JOIN ASISTENCIA a ON p.Id_Asistencia = a.Id_Asistencia
    WHERE p.Tipo_Participante = 200 AND p.Id_Actividad = ?
  `;

  // Ejecutar consulta con pool
  pool.query(query, [idActividad], (err, results) => {
    if (err) {
      console.error('Error al obtener usuarios inscritos:', err);
      return res.status(500).json({ error: 'Error al obtener usuarios inscritos' });
    }

    if (results.length === 0) {
      return res.status(404).json({ error: 'No se encontraron usuarios inscritos para la actividad proporcionada' });
    }

    res.status(200).json(results);
  });
});


// Actualizar asistencia de un usuario
app.put('/actualizar-asistencia', (req, res) => {
  const { Id_User, Id_Actividad, Id_Asistencia } = req.body;

  // Validar que todos los campos necesarios estén presentes
  if (!Id_User || !Id_Actividad || !Id_Asistencia) {
    return res.status(400).json({ error: 'Id_User, Id_Actividad e Id_Asistencia son requeridos.' });
  }

  const query = `
    UPDATE PARTICIPANTE 
    SET Id_Asistencia = ? 
    WHERE Id_User = ? AND Id_Actividad = ?
  `;

  // Ejecutar la consulta con pool
  pool.query(query, [Id_Asistencia, Id_User, Id_Actividad], (err, result) => {
    if (err) {
      console.error('Error al actualizar asistencia:', err);
      return res.status(500).json({ error: 'Error al actualizar la asistencia.' });
    }

    // Verificar si se actualizó algún registro
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'No se encontró la participación para actualizar.' });
    }

    res.status(200).json({ message: 'Asistencia actualizada exitosamente.' });
  });
});

app.post('/cambiarFavorito', (req, res) => {
  const { Id_SubCategoria, Id_User } = req.body;

  // Validar que los datos requeridos estén presentes
  if (!Id_SubCategoria || !Id_User) {
    return res.status(400).json({ error: 'Faltan datos requeridos: Id_SubCategoria e Id_User son obligatorios.' });
  }

  const query = `
    INSERT INTO FAVORITO (Id_User, Id_SubCategoria) 
    VALUES (?, ?) 
    ON DUPLICATE KEY UPDATE 
    Id_SubCategoria = VALUES(Id_SubCategoria);
  `;

  // Ejecutar la consulta con pool
  pool.query(query, [Id_User, Id_SubCategoria], (err, result) => {
    if (err) {
      console.error('Error al insertar o actualizar la Actividad Favorita:', err);
      return res.status(500).json({ error: 'Error al insertar o actualizar la Actividad Favorita.' });
    }

    // Devolver mensaje de éxito
    res.status(201).json({ message: 'Actividad Favorita insertada o actualizada exitosamente.' });
  });
});


app.get('/actividadFavorito', (req, res) => {
  const { Id_Comuna, Id_SubCategoria } = req.query;

  // Validar que los parámetros requeridos estén presentes
  if (!Id_Comuna || !Id_SubCategoria) {
    return res.status(400).json({ error: 'Faltan parámetros requeridos: Id_Comuna e Id_SubCategoria son obligatorios.' });
  }

  const query = `
    SELECT 
      a.Id_Actividad, 
      u.Nom_User, 
      a.Nom_Actividad, 
      a.Fecha_INI_Actividad, 
      DATE_FORMAT(a.Fecha_INI_Actividad, '%d/%m/%Y') AS Fecha_Inicio, 
      DATE_FORMAT(a.Fecha_INI_Actividad, '%H:%i') AS Hora_Inicio,
      a.Fecha_TER_Actividad, 
      DATE_FORMAT(a.Fecha_TER_Actividad, '%d/%m/%Y') AS Fecha_Termino, 
      DATE_FORMAT(a.Fecha_TER_Actividad, '%H:%i') AS Hora_Termino,
      a.Desc_Actividad, 
      a.Direccion_Actividad, 
      m.Cantidad_MaxJugador, 
      s.Nom_SubCategoria, 
      C.Nom_Categoria, 
      i.Url 
    FROM ACTIVIDAD a 
    INNER JOIN USUARIO u ON a.Id_Anfitrion_Actividad = u.Id_User 
    INNER JOIN MAXJUGADOR m ON a.Id_Maxjugador = m.Id_Maxjugador 
    INNER JOIN SUBCATEGORIA s ON s.Id_SubCategoria = a.Id_SubCategoria 
    INNER JOIN CATEGORIA C ON s.Id_Categoria = C.Id_Categoria 
    LEFT JOIN IMAGEN i ON s.Id_SubCategoria = i.Id_SubCategoria
    WHERE a.Id_Comuna = ? 
      AND s.Id_SubCategoria = ? 
      AND Fecha_INI_Actividad <= NOW() 
      AND Fecha_TER_Actividad >= NOW();
  `;

  // Ejecutar la consulta con pool
  pool.query(query, [Id_Comuna, Id_SubCategoria], (err, results) => {
    if (err) {
      console.error('Error al obtener actividades favoritas:', err);
      return res.status(500).json({ error: 'Error al obtener actividades favoritas.' });
    }

    // Responder con los resultados obtenidos
    res.status(200).json(results);
  });
});



// Endpoint para obtener datos de la tabla USUARIO
app.get('/usuarios', (req, res) => {
  const query = `
    SELECT 
      Id_User, 
      Run_User, 
      Tipo_User, 
      Nom_User, 
      Correo_User, 
      Id_Clasificacion 
    FROM USUARIO;
  `;

  pool.query(query, (err, results) => {
    if (err) {
      console.error('Error al obtener los datos de la tabla USUARIO:', err);
      return res.status(500).json({ error: 'Error al obtener los datos' });
    }

    res.status(200).json(results);
  });
});

// Iniciar el servidor
app.listen(port, () => {
  console.log(`Server running on https://backendplaytab-production.up.railway.app`);
});