const express = require('express');
const mysql = require('mysql2');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const cors = require('cors'); 
const app = express();
const port = 3000;
const bcrypt = require('bcryptjs');


app.use(cors()); 
app.use(express.json());

// Configuración de la base de datos
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '1111', // Cambia si tu contraseña es diferente
  database: 'PlayTab'
});

// Conexión a la base de datos MySQL
db.connect((err) => {
  if (err) {
    console.error('Error connecting to the database:', err);
    return;  }
  console.log('Connected to MySQL database');
});

// Comprobación y adición de la columna 'token' para recuperación de contraseña *******************
const verificarColumnaToken = () => {
  db.query(`SHOW COLUMNS FROM USUARIO LIKE 'token'`, (err, result) => {
    if (err) console.error(err);
    if (result.length === 0) {
      db.query(`ALTER TABLE USUARIO ADD COLUMN token VARCHAR(255)`, (alterErr) => {
        if (alterErr) console.error('Error al añadir la columna token:', alterErr);
        else console.log('Columna token añadida a la tabla USUARIO');
      });
    }
  });
};
verificarColumnaToken();

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
        auth: { user: 'playtab.app2024@gmail.com', pass: 'bgzp cihw gjca qoml' }
      });

      const resetUrl = `http://localhost:8100/reset-password/${token}`;
      const mailOptions = {
        from: 'playtab.app2024@gmail.com',
        to: correo,
        subject: 'Recuperación de contraseña',
        text: `Haz clic en el siguiente enlace para restablecer tu contraseña: ${resetUrl}`,
        html: `<p>Haz clic en el siguiente enlace para restablecer tu contraseña:</p><a href="${resetUrl}">${resetUrl}</a>`
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
    if (err) {
      return res.status(500).json({ error: 'Error en el servidor' });
    }
    if (results.length === 0) {
      return res.status(404).json({ error: 'Token inválido o expirado' });
    }

    try {
      const hashedPassword = await bcrypt.hash(newPassword, 10);

      const updatePasswordQuery = 'UPDATE USUARIO SET Contra_User = ?, token = NULL WHERE token = ?';
      db.query(updatePasswordQuery, [hashedPassword, token], (updateErr) => {
        if (updateErr) {
          return res.status(500).json({ error: 'Error al actualizar la contraseña' });
        }
        res.status(200).json({ message: 'Contraseña actualizada exitosamente' });
      });
    } catch (encryptionErr) {
      console.error('Error al encriptar la contraseña:', encryptionErr);
      res.status(500).json({ error: 'Error al procesar la nueva contraseña' });
    }
  });
});
// HASTA AQUÍ EL TEMA DE RECUPERAR CONTRASEÑA ******************************************

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
    Id_User, Tipo_User, Nom_User, Correo_User, Celular_User, 
    Contra_User, COMUNA.Id_Comuna, COMUNA.Nombre_Comuna, 
    REGION.Id_Region, REGION.Nombre_Region 
  FROM USUARIO 
  INNER JOIN COMUNA ON USUARIO.Id_Comuna = COMUNA.Id_Comuna 
  INNER JOIN REGION ON COMUNA.Id_Region = REGION.Id_Region 
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

    // Si la contraseña es válida, elimina la contraseña del objeto y responde
    delete user.Contra_User; // Elimina la contraseña encriptada antes de enviar la respuesta

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
  const query = 'SELECT a.Id_Actividad, u.Nom_User, a.Nom_Actividad, a.Fecha_INI_Actividad, a.Fecha_TER_Actividad, a.Desc_Actividad, a.Direccion_Actividad, m.Cantidad_MaxJugador, s.Nom_SubCategoria, C.Nom_Categoria, i.Url FROM ACTIVIDAD a Inner Join usuario u on a.Id_Anfitrion_Actividad = u.Id_User INNER JOIN maxjugador m ON a.Id_Maxjugador = m.Id_Maxjugador INNER JOIN subcategoria s ON s.Id_SubCategoria = a.Id_SubCategoria INNER JOIN CATEGORIA C ON s.Id_Categoria = C.Id_Categoria LEFT JOIN imagen i ON s.Id_SubCategoria = i.Id_SubCategoria WHERE a.Id_Comuna = ? AND Fecha_TER_Actividad>=now();';
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
  const query = 'SELECT COUNT(Id_Actividad) FROM `PlayTab`.`PARTICIPANTE` WHERE Id_Actividad = ?;';
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
  const { Id_Actividad, Id_Asistencia, Id_User } = req.body;

  if (!Id_Actividad || !Id_User) {
    return res.status(400).json({ error: 'Faltan datos requeridos' });
  }

  const query = `
    INSERT INTO PARTICIPANTE (Id_Actividad, Id_Asistencia, Id_User) 
    VALUES (?, ?, ?)
  `;

  db.query(query, [Id_Actividad, Id_Asistencia || 800, Id_User], (err, result) => {
    if (err) {
      console.error('Error al insertar participante:', err);
      return res.status(500).json({ error: 'Error al insertar participante' });
    }
    res.status(201).json({ message: 'Participante registrado exitosamente' });
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
  const query = `SELECT DISTINCT a.Nom_Actividad, u.Nom_User, a.Fecha_INI_Actividad, a.Fecha_TER_Actividad, s.Nom_SubCategoria, i.url
                  FROM Participante p
                  JOIN ACTIVIDAD a ON p.Id_Actividad = a.Id_Actividad
                  JOIN USUARIO u ON a.Id_Anfitrion_Actividad = u.Id_User
                  LEFT JOIN subcategoria s ON s.Id_SubCategoria = a.Id_SubCategoria
                  LEFT JOIN imagen i ON a.Id_SubCategoria = i.Id_SubCategoria
                  WHERE p.Id_User = ?;`
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
  const query = 'SELECT a.Id_Actividad, a.Nom_Actividad,i.Url,a.Fecha_TER_actividad, s.Nom_SubCategoria from participante p inner join Actividad a on p.Id_actividad=a.Id_actividad  inner join imagen i on a.Id_SubCategoria=i.Id_SubCategoria inner join subcategoria s on a.Id_subcategoria=s.Id_subcategoria where Id_user=?';
  db.query(query, [Id_User], (err, results) => {
    if (err) {
      console.error('Error al obtener actividades:', err);
      return res.status(500).json({ error: 'Error al obtener actividades' });
    }
    res.json(results);
  });
});
// Eliminar usuario de actividad
app.delete('/eliminar_usuario_actividad', (req, res) => {
  const { Id_User, Id_Actividad } = req.query;

  const query = 'DELETE FROM participante WHERE Id_user = ? AND Id_actividad = ?';
  db.query(query, [Id_User, Id_Actividad], (err, results) => {
    if (err) {
      console.error('Error al eliminar usuario de actividad:', err);
      return res.status(500).json({ error: 'Error al eliminar usuario de la actividad' });
    }
    res.status(200).json({ message: 'Usuario eliminado de la actividad' });
  });
});


// Iniciar el servidor
app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});
