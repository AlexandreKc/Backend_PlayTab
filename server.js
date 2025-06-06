const express = require('express');
const mysql = require('mysql2');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const cors = require('cors'); 
const app = express();
const port = 3000;
const bcrypt = require('bcryptjs');
require('dotenv').config();
const allowedOrigins = ['http://localhost:8100', 'http://backendplaytab-production.up.railway.app','https://localhost','http://localhost:8101'];

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
  credentials: true, // Permitir cookies y autenticación
}));
app.options('*', cors()); // Maneja solicitudes preflight para cualquier ruta
app.use(express.json());

// Configuración de la base de datos
let db;

function handleDisconnect() {
  db = mysql.createConnection({
    host: process.env.EV_HOST,
    user: process.env.EV_USERNAME,
    password: process.env.EV_PASS, 
    database: process.env.EV_NAME
  });

  // Conectar a la base de datos
  db.connect((err) => {
    if (err) {
      console.error('Error al conectar a la base de datos:', err);
      setTimeout(handleDisconnect, 2000); // Intentar reconectar después de 2 segundos
    } else {
      console.log('Conexión a la base de datos restablecida.');
    }
  });

  // Manejar errores de conexión
  db.on('error', (err) => {
    console.error('Error de conexión a la base de datos:', err);
    if (err.code === 'PROTOCOL_CONNECTION_LOST') {
      console.log('Intentando restablecer la conexión...');
      handleDisconnect(); // Reconectar automáticamente
    } else {
      throw err; // Lanza otros errores
    }
  });
}

// Inicializar la conexión
handleDisconnect();

// Mantener la conexión activa
setInterval(() => {
  db.ping((err) => {
    if (err) {
      console.error('Error al hacer ping a la base de datos:', err);
    } else {
      console.log('Ping exitoso a la base de datos.');
    }
  });
}, 60000); // Ping cada 60 segundos


// Rutas y funciones para la recuperación de contraseña **************************************
app.post('/recover-password', (req, res) => {
  const { RUT, correo } = req.body;

  if (!RUT || !correo) return res.status(400).json({ error: 'RUT y correo son requeridos' });

  const query = 'SELECT * FROM USUARIO WHERE Run_User = ? AND Correo_User = ?';
  db.query(query, [RUT, correo], (err, results) => {
    if (err) return res.status(500).json({ error: 'Error en el servidor' });
    if (results.length === 0) return res.status(404).json({ error: 'Usuario no encontrado' });

    const token = crypto.randomBytes(20).toString('hex');
    const updateTokenQuery = 'UPDATE USUARIO SET token = ? WHERE Run_User = ?';
    db.query(updateTokenQuery, [token, RUT], (updateErr) => {
      if (updateErr) return res.status(500).json({ error: 'Error en el servidor' });

      const transporter = nodemailer.createTransport({
        service: 'Gmail',
        auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS }
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
        if (error) return res.status(500).json({ error: 'Error enviando el correo' });
        res.status(200).json({ message: 'Código de recuperación enviado' });
      });
    });
  });
});

app.post('/reset-password', async (req, res) => {
  const { token, newPassword } = req.body;

  if (!token || !newPassword) {
    return res.status(400).json({ error: 'Token y nueva contraseña son requeridos' });
  }

  const query = 'SELECT * FROM USUARIO WHERE token = ?';
  db.query(query, [token], async (err, results) => {
    if (err) return res.status(500).json({ error: 'Error en el servidor' });
    if (results.length === 0) return res.status(404).json({ error: 'Token inválido o expirado' });

    try {
      const hashedPassword = await bcrypt.hash(newPassword, 10);

      const updatePasswordQuery = 'UPDATE USUARIO SET Contra_User = ?, token = NULL WHERE token = ?';
      db.query(updatePasswordQuery, [hashedPassword, token], (updateErr) => {
        if (updateErr) return res.status(500).json({ error: 'Error al actualizar la contraseña' });
        res.status(200).json({ message: 'Contraseña actualizada exitosamente' });
      });
    } catch (hashErr) {
      console.error('Error al encriptar la contraseña:', hashErr);
      res.status(500).json({ error: 'Error interno del servidor' });
    }
  });
});
// HASTA AQUÍ EL TEMA DE RECUPERAR CONTRASEÑA ******************************************

app.get('/api/maps-key', (req, res) => {
  const apiKey = process.env.EV_MAPS; // Tu API Key
  res.json({ apiKey });
});

// 1. Aquí se obtendrá las Regiones y Comunas disponibles para poder registrar al usuario.
app.get('/regiones', (req, res) => {
  const query = 'SELECT * FROM REGION';
  db.query(query, (err, results) => { 
    if (err) {
      res.status(500).send(err);
    } else {
      res.json(results);
    }
  });
});

// Obtener las comunas por id de la región.
app.get('/comunas/:regionId', (req, res) => {
  const regionId = req.params.regionId; // Obtiene el id de la región desde la URL
  const query = 'SELECT * FROM COMUNA WHERE Id_Region = ?';
  db.query(query, [regionId], (err, results) => {
    if (err) {
      res.status(500).send(err);
    } else {
      res.json(results);
    }
  });
});

// 2. Aquí se realizará el INSERT del usuario. 
app.post('/register', async (req, res) => {
  const { Run_User, Nom_User, Correo_User, Contra_User, Celular_User, FechaNac_User, Id_Comuna } = req.body;

  if (!Run_User || !Nom_User || !Correo_User || !Contra_User || !Celular_User || !FechaNac_User || !Id_Comuna) {
    return res.status(400).json({ error: 'Faltan datos requeridos' });
  }

  const hashedPassword = await bcrypt.hash(Contra_User, 10);
  
  const query = `INSERT INTO USUARIO (Run_User ,Tipo_User , Nom_User, Correo_User, Contra_User, Celular_User, FechaNac_User, FechaCreacion_User, Id_Comuna, Id_Estado) 
                 VALUES (?, 101, ?, ?, ?, ?, ?, NOW(), ?, 15)`;

  db.query(query, [Run_User, Nom_User, Correo_User, hashedPassword, Celular_User, FechaNac_User, Id_Comuna], (err, result) => {
    if (err) {
      console.error('Error inserting user:', err);
      if (err.code === 'ER_DUP_ENTRY') {
        return res.status(409).json({ error: 'El usuario ya existe' });
      }
      return res.status(500).json({ error: 'Error al registrar el usuario' });
    }
    res.status(201).json({ message: 'Usuario registrado exitosamente' });
  });
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

  if (!Nom_Actividad || !Desc_Actividad || !Direccion_Actividad || !Id_MaxJugador || !Fecha_INI_Actividad || !Fecha_TER_Actividad || !Id_Comuna || !Id_SubCategoria || !Id_Estado || !Id_Anfitrion_Actividad ||!Celular_User) {
    return res.status(400).json({ error: 'Faltan datos requeridos' });
  }

  const query = `
    INSERT INTO ACTIVIDAD 
    (Nom_Actividad, Desc_Actividad, Direccion_Actividad, Id_MaxJugador, Fecha_INI_Actividad, Fecha_TER_Actividad, Id_Comuna, Id_SubCategoria, Id_Estado, Id_Anfitrion_Actividad, Celular_User) 
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `;
  db.query(query, [
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
  ], (err, result) => {
    if (err) {
      console.error('Error inserting actividad:', err);
      if (err.code === 'ER_DUP_ENTRY') {
        return res.status(409).json({ error: 'La Actividad ya existe' });
      }
      return res.status(500).json({ error: 'Error al registrar la actividad' });
    }
    res.status(201).json({ message: 'Actividad registrada exitosamente', id: result.insertId });
  });
});

// Ruta para el login del usuario (Obtener los datos de la consulta)
app.post('/login', (req, res) => {
  const { Correo_User, Contra_User } = req.body;

  if (!Correo_User || !Contra_User) {
    return res.status(400).json({ error: 'Correo y contraseña son requeridos' });
  }

  const query = `
  SELECT 
    USUARIO.Id_User, USUARIO.Tipo_User, USUARIO.Nom_User, USUARIO.Correo_User, USUARIO.Celular_User, 
    USUARIO.Contra_User, COMUNA.Id_Comuna, COMUNA.Nombre_Comuna, 
    REGION.Id_Region, REGION.Nombre_Region, SUBCATEGORIA.Id_SubCategoria ,SUBCATEGORIA.Nom_SubCategoria
  FROM USUARIO 
  INNER JOIN COMUNA ON USUARIO.Id_Comuna = COMUNA.Id_Comuna 
  INNER JOIN REGION ON COMUNA.Id_Region = REGION.Id_Region
  LEFT JOIN FAVORITO ON USUARIO.Id_User=FAVORITO.Id_User
  LEFT JOIN SUBCATEGORIA ON FAVORITO.Id_SubCategoria=SUBCATEGORIA.Id_SubCategoria
  WHERE Correo_User = ?`;

  db.query(query, [Correo_User], async (err, result) => {
    if (err) {
      console.error('Error during login:', err);
      return res.status(500).json({ error: 'Error en el servidor' });
    }

    if (result.length === 0) {
      return res.status(401).json({ error: 'Credenciales inválidas' });
    }

    const user = result[0];

    // Verifica la contraseña con bcrypt
    const isPasswordValid = await bcrypt.compare(Contra_User, user.Contra_User);

    if (!isPasswordValid) {
      return res.status(401).json({ error: 'Credenciales inválidas' });
    }
    
    delete user.Contra_User;

    res.status(200).json({ message: 'Login exitoso', user });
  });
});

// 3. Aquí se obtendrá las Categoria y subcategoria 
app.get('/categoria', (req, res) => {
  const query = 'SELECT * FROM CATEGORIA';
  db.query(query, (err, results) => { 
    if (err) {
      res.status(500).send(err);
    } else {
      res.json(results);
    }
  });
});

app.get('/subcategoria/:categoriaId', (req, res) => {
  const categoriaId = req.params.categoriaId; 
  const query = 'SELECT * FROM SUBCATEGORIA WHERE Id_Categoria = ?';
  db.query(query, [categoriaId], (err, results) => {
    if (err) {
      res.status(500).send(err);
    } else {
      res.json(results);
    }
  });
});

// 4. Aquí se obtendrá los jugadores máximos
app.get('/cantidad', (req, res) => {
  const query = 'SELECT * FROM MAXJUGADOR';
  db.query(query, (err, results) => { 
    if (err) {
      res.status(500).send(err);
    } else {
      res.json(results);
    }
  });
});

// 5. Este es para obtener las actividades
app.get('/actividades', (req, res) => {
  const { Id_Comuna } = req.query;
  const query = `SELECT a.Id_Actividad, u.Nom_User, 
                  a.Nom_Actividad, 
                  a.Fecha_INI_Actividad, DATE_FORMAT(a.Fecha_INI_Actividad, '%d/%m/%Y') AS Fecha_Inicio, DATE_FORMAT(a.Fecha_INI_Actividad, '%H:%i') AS Hora_Inicio,
                  a.Fecha_TER_Actividad, DATE_FORMAT(a.Fecha_TER_Actividad, '%d/%m/%Y') AS Fecha_Termino, DATE_FORMAT(a.Fecha_TER_Actividad, '%H:%i') AS Hora_Termino,
                  a.Desc_Actividad, 
                  a.Direccion_Actividad, 
                  m.Cantidad_MaxJugador, 
                  s.Nom_SubCategoria, 
                  C.Nom_Categoria, i.Url 
                          FROM ACTIVIDAD a Inner Join USUARIO u on a.Id_Anfitrion_Actividad = u.Id_User 
                          INNER JOIN MAXJUGADOR m ON a.Id_Maxjugador = m.Id_Maxjugador 
                          INNER JOIN SUBCATEGORIA s ON s.Id_SubCategoria = a.Id_SubCategoria 
                          INNER JOIN CATEGORIA C ON s.Id_Categoria = C.Id_Categoria 
                          LEFT JOIN IMAGEN i ON s.Id_SubCategoria = i.Id_SubCategoria
                          WHERE a.Id_Comuna = ? AND Fecha_INI_Actividad<=now() and Fecha_TER_Actividad>=now();`;
  db.query(query, [Id_Comuna], (err, results) => {
    if (err) {
      console.error('Error al obtener actividades:', err);
      return res.status(500).json({ error: 'Error al obtener actividades' });
    }
    res.json(results);
  });
});

app.get('/jugdoresInscritos', (req, res) => {
  const { Id_Actividad } = req.query;
  const query = 'SELECT COUNT(Id_Actividad) FROM PARTICIPANTE WHERE Id_Actividad = ?;';
  db.query(query, [Id_Actividad], (err, results) => {
    if (err) {
      console.error('Error:', err);
      return res.status(500).json({ error: 'Error al obtener los jugadores inscritos' });
    }
    res.json(results);
  });
});

// insertar participante en la Actividad
app.post('/participante', (req, res) => {
  const { Id_Actividad, Id_Asistencia, Id_User, Tipo_Participante } = req.body;

  if (!Id_Actividad || !Id_User) {
    return res.status(400).json({ error: 'Faltan datos requeridos' });
  }

  const query = `
    INSERT INTO PARTICIPANTE (Id_Actividad, Id_Asistencia, Id_User, Tipo_Participante) 
    VALUES (?, ?, ?, ?)
  `;

  db.query(query, [Id_Actividad, Id_Asistencia || 800, Id_User, Tipo_Participante], (err, result) => {
    if (err) {
      console.error('Error al insertar participante:', err);
      return res.status(500).json({ error: 'Error al insertar participante' });
    }
    res.status(201).json({ message: 'Participante registrado exitosamente' });
  });
});


// Cambiar la comuna
app.put('/cambiaComuna', (req, res) => {
  const { Id_Comuna, Id_User } = req.body;

  if (!Id_Comuna || !Id_User) {
    return res.status(400).json({ error: 'Faltan datos requeridos' });
  }

  const query = `
    UPDATE USUARIO 
    SET Id_Comuna= ? 
    WHERE Id_User = ?;
  `;

  db.query(query, [Id_Comuna, Id_User], (err, result) => {
    if (err) {
      console.error('Error al actualizar la comuna:', err);
      return res.status(500).json({ error: 'Error al actualizar la comuna' });
    }
    res.status(201).json({ message: 'Comuna actualizada exitosamente' });
  });
});

//Ver el historial de actividades
app.get('/historial', (req, res) => {
  const { Id_User } = req.query;
  const query = `SELECT DISTINCT u.Nom_User, a.Nom_Actividad, a.Desc_actividad, a.Direccion_Actividad, a.Celular_User, a.Fecha_TER_Actividad, s.Nom_SubCategoria, i.url
                  FROM PARTICIPANTE p
                  JOIN ACTIVIDAD a ON p.Id_Actividad = a.Id_Actividad
                  JOIN USUARIO u ON a.Id_Anfitrion_Actividad = u.Id_User
                  LEFT JOIN SUBCATEGORIA s ON s.Id_SubCategoria = a.Id_SubCategoria
                  LEFT JOIN IMAGEN i ON a.Id_SubCategoria = i.Id_SubCategoria
                  WHERE p.Id_User = ?
                  order by a.Fecha_TER_Actividad desc;`
  db.query(query, [Id_User], (err, results) => {
    if (err) {
      console.error('Error al obtener el historial:', err);
      return res.status(500).json({ error: 'Error al obtener el historial' });
    }
    res.json(results);
  });
});

// Obtener actividades y datos especificos de la actividad de los usuarios inscritos
app.get('/actividad_activa', (req, res) => {
  const { Id_User } = req.query;
  const query = `SELECT DISTINCT a.Nom_Actividad, 
                                a.Id_Actividad, 
                                u.Nom_User, 
                                a.Desc_Actividad, 
                                u.Celular_User, 
                                a.Direccion_Actividad, 
                                m.Cantidad_MaxJugador, 
                                a.Fecha_TER_Actividad, DATE_FORMAT(a.Fecha_TER_Actividad, '%d/%m/%Y') AS Fecha_Termino, DATE_FORMAT(a.Fecha_TER_Actividad, '%H:%i') AS Hora_Termino,
                                p.Tipo_Participante, 
                                s.Nom_SubCategoria, i.Url
                  FROM PARTICIPANTE p
                  JOIN ACTIVIDAD a ON p.Id_Actividad = a.Id_Actividad
                  INNER JOIN MAXJUGADOR m ON a.Id_Maxjugador = m.Id_Maxjugador
                  JOIN USUARIO u ON a.Id_Anfitrion_Actividad = u.Id_User
                  LEFT JOIN SUBCATEGORIA s ON s.Id_SubCategoria = a.Id_SubCategoria
                  LEFT JOIN IMAGEN i ON a.Id_SubCategoria = i.Id_SubCategoria
                  WHERE p.Id_User = ? AND  p.Tipo_Participante=200 and Fecha_INI_Actividad<=now() and Fecha_TER_Actividad>=now();`;
  db.query(query, [Id_User], (err, results) => {
    if (err) {
      console.error('Error al obtener actividades:', err);
      return res.status(500).json({ error: 'Error al obtener actividades inscritas' });
    }
    res.json(results);
  });
});

// Eliminar usuario de actividad
app.delete('/eliminar_usuario_actividad', (req, res) => {
  const { Id_User, Id_Actividad } = req.query;

  const query = 'DELETE FROM PARTICIPANTE WHERE Id_user = ? AND Id_actividad = ?';
  db.query(query, [Id_User, Id_Actividad], (err, results) => {
    if (err) {
      console.error('Error al eliminar usuario de actividad:', err);
      return res.status(500).json({ error: 'Error al eliminar usuario de la actividad' });
    }
    res.status(200).json({ message: 'Usuario eliminado de la actividad' });
  });
});

app.get('/actividadesAnfitrion', (req, res) => {
  const { Id_User } = req.query; // Usamos Id_User desde la query en lugar de Id_Anfitrion_Actividad
  const query = `
      SELECT a.Id_Actividad, a.Nom_Actividad, 
      a.Desc_actividad, a.Direccion_Actividad, 
      m.Cantidad_MaxJugador, 
      u.Nom_User, 
      a.Fecha_INI_Actividad, DATE_FORMAT(a.Fecha_INI_Actividad, '%d/%m/%Y') AS Fecha_Inicio, DATE_FORMAT(a.Fecha_INI_Actividad, '%H:%i') AS Hora_Inicio,
      a.Fecha_TER_Actividad, DATE_FORMAT(a.Fecha_TER_Actividad, '%d/%m/%Y') AS Fecha_Termino, DATE_FORMAT(a.Fecha_TER_Actividad, '%H:%i') AS Hora_Termino,
      i.Url, s.Id_SubCategoria, 
      s.Id_Categoria, 
      s.Nom_SubCategoria
      FROM ACTIVIDAD a
      INNER JOIN USUARIO u ON a.Id_Anfitrion_Actividad=u.Id_User
      JOIN IMAGEN i on a.Id_SubCategoria=i.Id_SubCategoria
      JOIN SUBCATEGORIA s ON a.Id_SubCategoria= s.Id_SubCategoria
      JOIN CATEGORIA c on s.Id_Categoria=c.Id_Categoria
      JOIN MAXJUGADOR m on a.Id_MaxJugador=m.Id_MaxJugador
      WHERE Id_Anfitrion_Actividad=? and DATE(a.Fecha_INI_Actividad) = CURDATE()
      order by a.Fecha_TER_Actividad asc;
    `;
  db.query(query, [Id_User], (err, results) => {
    if (err) {
      console.error('Error al obtener actividades de anfitrión:', err);
      return res.status(500).json({ error: 'Error al obtener actividades del anfitrión' });
    }
    res.json(results);
  });
});

// Actualizar actividad
app.put('/updateActividad/:id', (req, res) => {
  const Id_Actividad = req.params.id;
  const { Desc_Actividad, Direccion_Actividad, Id_MaxJugador } = req.body;

  console.log('Datos recibidos:', { Desc_Actividad, Direccion_Actividad, Id_MaxJugador });

  const query = `
    UPDATE ACTIVIDAD 
    SET Desc_Actividad = ?, Direccion_Actividad = ?, Id_MaxJugador = ?
    WHERE Id_Actividad = ?
  `;

  db.query(query, [Desc_Actividad, Direccion_Actividad, Id_MaxJugador, Id_Actividad], (err, result) => {
    if (err) {
      console.error('Error al actualizar actividad:', err);
      return res.status(500).json({ error: 'Error al actualizar la actividad' });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Actividad no encontrada' });
    }
    res.status(200).json({ message: 'Actividad actualizada exitosamente' });
  });
});

// Eliminar la actividad.
app.delete('/actividad/:id', (req, res) => {
  const Id_Actividad = req.params.id;
  const query = 'DELETE FROM ACTIVIDAD WHERE Id_Actividad = ?';

  db.query(query, [Id_Actividad], (err, result) => {
    if (err) {
      console.error('Error al eliminar actividad:', err);
      return res.status(500).json({ error: 'Error al eliminar la actividad' });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'La actividad no existe' });
    }
    res.status(200).json({ message: 'Actividad eliminada exitosamente' });
  });
});

app.get('/usuarios-inscritos/:idActividad', (req, res) => {
  const { idActividad } = req.params;
  const query = `
    SELECT DISTINCT u.Id_User, u.Nom_User, u.Celular_User, a.Tipo_Asistencia 
    FROM PARTICIPANTE p
    INNER JOIN USUARIO u ON p.Id_User = u.Id_User
    LEFT JOIN ASISTENCIA a ON p.Id_Asistencia = a.Id_Asistencia
    WHERE p.Tipo_Participante = 200 AND p.Id_Actividad = ?
  `;

  db.query(query, [idActividad], (err, results) => {
    if (err) {
      console.error('Error al obtener usuarios inscritos:', err);
      return res.status(500).json({ error: 'Error al obtener usuarios inscritos' });
    }
    res.json(results);
  });
});

// Actualizar asistencia de un usuario
app.put('/actualizar-asistencia', (req, res) => {
  const { Id_User, Id_Actividad, Id_Asistencia } = req.body;

  const query = `
    UPDATE PARTICIPANTE 
    SET Id_Asistencia = ? 
    WHERE Id_User = ? AND Id_Actividad = ?
  `;

  db.query(query, [Id_Asistencia, Id_User, Id_Actividad], (err, result) => {
    if (err) {
      console.error('Error al actualizar asistencia:', err);
      return res.status(500).json({ error: 'Error al actualizar la asistencia' });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'No se encontró la participación para actualizar.' });
    }
    res.status(200).json({ message: 'Asistencia actualizada exitosamente.' });
  });
});

app.post('/cambiarFavorito', (req, res) => {
  const { Id_SubCategoria, Id_User } = req.body;

  if (!Id_SubCategoria || !Id_User) {
    return res.status(400).json({ error: 'Faltan datos requeridos' });
  }

  const query = `
    INSERT INTO FAVORITO (Id_User, Id_SubCategoria) 
    VALUES (?, ?) 
    ON DUPLICATE KEY UPDATE 
    Id_SubCategoria = VALUES(Id_SubCategoria);
  `;

  db.query(query, [Id_User, Id_SubCategoria], (err, result) => {
    if (err) {
      console.error('Error al insertar o actualizar tu Actividad Favorita:', err);
      return res.status(500).json({ error: 'Error al insertar o actualizar tu Actividad Favorita.' });
    }
    res.status(201).json({ message: 'Actividad Favorita insertada o actualizada.' });
  });
});

app.get('/actividadFavorito', (req, res) => {
  const { Id_Comuna } = req.query;
  const { Id_SubCategoria } = req.query;
  const query = `SELECT a.Id_Actividad, u.Nom_User, 
                  a.Nom_Actividad, 
                  a.Fecha_INI_Actividad, DATE_FORMAT(a.Fecha_INI_Actividad, '%d/%m/%Y') AS Fecha_Inicio, DATE_FORMAT(a.Fecha_INI_Actividad, '%H:%i') AS Hora_Inicio,
                  a.Fecha_TER_Actividad, DATE_FORMAT(a.Fecha_TER_Actividad, '%d/%m/%Y') AS Fecha_Termino, DATE_FORMAT(a.Fecha_TER_Actividad, '%H:%i') AS Hora_Termino,
                  a.Desc_Actividad, 
                  a.Direccion_Actividad, 
                  m.Cantidad_MaxJugador, 
                  s.Nom_SubCategoria, 
                  C.Nom_Categoria, i.Url 
                          FROM ACTIVIDAD a Inner Join USUARIO u on a.Id_Anfitrion_Actividad = u.Id_User 
                          INNER JOIN MAXJUGADOR m ON a.Id_Maxjugador = m.Id_Maxjugador 
                          INNER JOIN SUBCATEGORIA s ON s.Id_SubCategoria = a.Id_SubCategoria 
                          INNER JOIN CATEGORIA C ON s.Id_Categoria = C.Id_Categoria 
                          LEFT JOIN IMAGEN i ON s.Id_SubCategoria = i.Id_SubCategoria
                          WHERE a.Id_Comuna =? AND s.Id_SubCategoria=? AND Fecha_INI_Actividad<=now() and Fecha_TER_Actividad>=now();`;
  db.query(query, [Id_Comuna, Id_SubCategoria], (err, results) => {
    if (err) {
      console.error('Error al obtener actividades favoritas:', err);
      return res.status(500).json({ error: 'Error al obtener actividades favoritas' });
    }
    res.json(results);
  });
});


// Endpoint para obtener datos de la tabla USUARIO
app.get('/usuarios', (req, res) => {
  const query = `
    SELECT 
    u.Id_User, 
    u.Run_User, 
    u.Tipo_User, 
    u.Nom_User, 
    u.Correo_User, 
    u.Celular_User,
    u.FechaNac_User,
    c.Id_Comuna,
    r.Id_Region,
    c.Nombre_Comuna,
    r.Nombre_Region,
    (SELECT 
            (SELECT COUNT(ID_ASISTENCIA)
             FROM PARTICIPANTE p1
             WHERE p1.ID_ASISTENCIA = 800 
               AND p1.ID_USER = u.Id_User 
               AND p1.TIPO_PARTICIPANTE = 200) /
            (SELECT COUNT(ID_ACTIVIDAD)
             FROM PARTICIPANTE p2
             WHERE p2.ID_USER = u.Id_User 
               AND p2.TIPO_PARTICIPANTE = 200)
    ) AS Rating
    FROM USUARIO u
    INNER JOIN COMUNA c ON u.Id_Comuna = c.Id_Comuna
    INNER JOIN REGION r ON c.Id_Region = r.Id_Region;
  `;
  db.query(query, (err, results) => {
    if (err) {
      console.error('Error al obtener los datos de la tabla USUARIO:', err);
      return res.status(500).json({ error: 'Error al obtener los datos de la tabla USUARIO' });
    }
    res.status(200).json(results);
  });
});

//Eliminar Usuario
app.delete('/borrarUser/:Id_User', (req, res) => {
  const Id_User = req.params.Id_User;
  const deleteQuery = 'DELETE FROM USUARIO WHERE Id_User = ?';

  db.query(deleteQuery, [Id_User], (err, result) => {
    if (err) {
      console.error(err);
      return res.status(500).send('Error al eliminar el usuario >:(');
    } else if (result.affectedRows === 0) {
      return res.status(404).send('Usuario no encontrado :(');
    } else {
      res.status(200).json({ message: 'Usuario eliminado con éxito :D' });
    }
  });
});
//Este endpoint será para los cambio de datos que tendrá el administrador
app.put('/update-usuario/:Id_User', (req, res) => {
  const { Id_User } = req.params;
  const { Tipo_User, Nom_User, Correo_User, Celular_User, Id_Comuna } = req.body;

  if (!Id_User || !Tipo_User || !Nom_User || !Correo_User || !Celular_User || !Id_Comuna) {
    return res.status(400).json({ error: 'Faltan datos requeridos para la actualización.' });
  }

  const query = `
    UPDATE USUARIO u
    INNER JOIN COMUNA c ON u.Id_Comuna = c.Id_Comuna
    INNER JOIN REGION r ON c.Id_Region = r.Id_Region
    SET 
      u.Tipo_User = ?, 
      u.Nom_User = ?, 
      u.Correo_User = ?, 
      u.Celular_User = ?, 
      u.Id_Comuna = ?
    WHERE u.Id_User = ?;
  `;

  db.query(
    query,
    [Tipo_User, Nom_User, Correo_User, Celular_User, Id_Comuna, Id_User],
    (err, result) => {
      if (err) {
        console.error('Error al actualizar el usuario:', err);
        return res.status(500).json({ error: 'Error al actualizar el usuario.' });
      }

      if (result.affectedRows === 0) {
        return res.status(404).json({ error: 'Usuario no encontrado.' });
      }

      res.status(200).json({ message: 'Usuario actualizado exitosamente.' });
    }
  );
});
// Obtener todas las comunas existentes
app.get('/comunas', (req, res) => {
  const query = 'SELECT * FROM COMUNA'; // Consulta para obtener todas las comunas
  
  db.query(query, (err, results) => {
    if (err) {
      console.error('Error al obtener las comunas:', err);
      return res.status(500).json({ error: 'Error al obtener las comunas.' });
    }
    res.status(200).json(results); // Enviar el resultado como JSON
  });
});

// Iniciar el servidor
app.listen(port, () => {
  console.log(`Server running on https://backendplaytab-production.up.railway.app`);
});