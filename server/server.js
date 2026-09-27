require("dotenv").config();

const path = require("path");
const fs = require("fs");
const crypto = require("crypto");

const express = require("express");
const bcrypt = require("bcrypt");
const multer = require("multer");
const session = require("express-session");
const connectPgSimple = require("connect-pg-simple");

const pool = require("./db");


/* =========================================================
   APP CONFIG
========================================================= */

const app = express();

const PORT =
  Number(process.env.PORT) || 3000;

const isProduction =
  process.env.NODE_ENV === "production";

const SESSION_SECRET =
  process.env.SESSION_SECRET;

if (!SESSION_SECRET) {
  throw new Error(
    "SESSION_SECRET belum diatur di file .env"
  );
}


/* =========================================================
   PATH
========================================================= */

const publicDir =
  path.join(
    __dirname,
    "..",
    "public"
  );

const uploadDir =
  path.join(
    __dirname,
    "..",
    "storage",
    "uploads"
  );


/* =========================================================
   PASTIKAN FOLDER UPLOAD ADA
========================================================= */

fs.mkdirSync(
  uploadDir,
  {
    recursive: true
  }
);


/* =========================================================
   MULTER UPLOAD
========================================================= */

const allowedExtensions = [
  ".pdf",
  ".doc",
  ".docx"
];


const uploadStorage =
  multer.diskStorage({

    destination:
      (req, file, cb) => {

        cb(
          null,
          uploadDir
        );

      },

    filename:
      (req, file, cb) => {

        const originalExt =
          path
            .extname(
              file.originalname
            )
            .toLowerCase();


        const originalBase =
          path
            .basename(
              file.originalname,
              originalExt
            )
            .replace(
              /[^a-zA-Z0-9_-]/g,
              "_"
            )
            .slice(
              0,
              80
            );


        const uniqueId =
          crypto
            .randomBytes(12)
            .toString("hex");


        const storedFileName =
          `${Date.now()}-${uniqueId}-${originalBase}${originalExt}`;


        cb(
          null,
          storedFileName
        );

      }

  });


const upload =
  multer({

    storage:
      uploadStorage,

    limits: {
      fileSize:
        10 * 1024 * 1024
    },

    fileFilter:
      (req, file, cb) => {

        const extension =
          path
            .extname(
              file.originalname
            )
            .toLowerCase();


        if (
          !allowedExtensions.includes(
            extension
          )
        ) {

          return cb(
            new Error(
              "File harus berformat PDF, DOC, atau DOCX."
            )
          );

        }


        cb(
          null,
          true
        );

      }

  });


/* =========================================================
   UPLOAD ERROR HANDLER
========================================================= */

function uploadReport(
  req,
  res,
  next
) {

  upload.single(
    "report_file"
  )(
    req,
    res,
    error => {

      if (!error) {
        return next();
      }


      if (
        error instanceof
        multer.MulterError
      ) {

        if (
          error.code ===
          "LIMIT_FILE_SIZE"
        ) {

          return res
            .status(400)
            .json({
              success: false,
              message:
                "Ukuran file maksimal 10 MB."
            });

        }


        return res
          .status(400)
          .json({
            success: false,
            message:
              `Upload file gagal: ${error.message}`
          });

      }


      return res
        .status(400)
        .json({
          success: false,
          message:
            error.message ||
            "Upload file gagal."
        });

    }
  );

}


/* =========================================================
   PROXY
========================================================= */

if (isProduction) {

  app.set(
    "trust proxy",
    1
  );

}


/* =========================================================
   MIDDLEWARE
========================================================= */

app.use(
  express.json({
    limit: "2mb"
  })
);

app.use(
  express.urlencoded({
    extended: true,
    limit: "2mb"
  })
);


/* =========================================================
   SESSION STORE
========================================================= */

const PgStore =
  connectPgSimple(
    session
  );


app.use(
  session({

    store:
      new PgStore({

        pool,

        tableName:
          "user_sessions",

        createTableIfMissing:
          true

      }),

    secret:
      SESSION_SECRET,

    resave:
      false,

    saveUninitialized:
      false,

    rolling:
      true,

    cookie: {

      httpOnly:
        true,

      secure:
        isProduction,

      sameSite:
        "lax",

      maxAge:
        8 * 60 * 60 * 1000

    }

  })
);


/* =========================================================
   STATIC PUBLIC
========================================================= */

app.use(
  express.static(
    publicDir
  )
);


/* =========================================================
   AUTH HELPERS
========================================================= */

async function getAuthenticatedUser(
  req
) {

  if (
    !req.session ||
    !req.session.userId
  ) {

    return null;

  }


  const result =
    await pool.query(
      `
        SELECT
          id,
          nim,
          name,
          role,
          created_at
        FROM users
        WHERE id = $1
        LIMIT 1
      `,
      [
        req.session.userId
      ]
    );


  if (
    result.rowCount ===
    0
  ) {

    return null;

  }


  return result.rows[0];

}


async function requireLogin(
  req,
  res,
  next
) {

  try {

    const user =
      await getAuthenticatedUser(
        req
      );


    if (!user) {

      return res
        .status(401)
        .json({
          success: false,
          message:
            "Kamu belum login."
        });

    }


    req.user =
      user;


    next();

  } catch (error) {

    next(error);

  }

}


function requireRole(
  ...allowedRoles
) {

  return async (
    req,
    res,
    next
  ) => {

    try {

      const user =
        await getAuthenticatedUser(
          req
        );


      if (!user) {

        return res
          .status(401)
          .json({
            success: false,
            message:
              "Kamu belum login."
          });

      }


      if (
        !allowedRoles.includes(
          user.role
        )
      ) {

        return res
          .status(403)
          .json({
            success: false,
            message:
              "Kamu tidak memiliki akses ke fitur ini."
          });

      }


      req.user =
        user;


      next();

    } catch (error) {

      next(error);

    }

  };

}


/* =========================================================
   VALIDATION HELPERS
========================================================= */

function isPositiveInteger(
  value
) {

  return (
    Number.isInteger(
      Number(value)
    ) &&
    Number(value) > 0
  );

}


function cleanString(
  value
) {

  return String(
    value ?? ""
  ).trim();

}


function isValidDateString(
  value
) {

  return /^\d{4}-\d{2}-\d{2}$/.test(
    String(value)
  );

}


function isValidTimeString(
  value
) {

  return /^\d{2}:\d{2}$/.test(
    String(value)
  );

}


/* =========================================================
   DB TEST
========================================================= */

app.get(
  "/db-test",
  async (
    req,
    res,
    next
  ) => {

    try {

      const result =
        await pool.query(
          "SELECT NOW() AS now"
        );


      return res.json({
        success: true,
        message:
          "Database terhubung.",
        now:
          result.rows[0].now
      });

    } catch (error) {

      next(error);

    }

  }
);


/* =========================================================
   CURRENT USER
========================================================= */

app.get(
  "/me",
  async (
    req,
    res,
    next
  ) => {

    try {

      const user =
        await getAuthenticatedUser(
          req
        );


      if (!user) {

        return res
          .status(401)
          .json({
            success: true,
            authenticated:
              false,
            user:
              null
          });

      }


      return res.json({
        success: true,
        authenticated:
          true,
        user
      });

    } catch (error) {

      next(error);

    }

  }
);


/* =========================================================
   LOGOUT
========================================================= */

app.post(
  "/logout",
  async (
    req,
    res,
    next
  ) => {

    try {

      if (
        req.session
      ) {

        req.session.destroy(
          error => {

            if (error) {
              return next(error);
            }


            res.clearCookie(
              "connect.sid"
            );


            return res.json({
              success: true,
              message:
                "Logout berhasil."
            });

          }
        );

        return;

      }


      return res.json({
        success: true,
        message:
          "Logout berhasil."
      });

    } catch (error) {

      next(error);

    }

  }
);


/* =========================================================
   USERS - GET
========================================================= */

app.get(
  "/users",
  requireLogin,
  async (
    req,
    res,
    next
  ) => {

    try {

      let result;


      if (
        req.user.role ===
        "admin"
      ) {

        result =
          await pool.query(
            `
              SELECT
                id,
                nim,
                name,
                role,
                created_at
              FROM users
              ORDER BY id ASC
            `
          );

      } else {

        result =
          await pool.query(
            `
              SELECT
                id,
                nim,
                name,
                role,
                created_at
              FROM users
              WHERE role = 'asisten'
              ORDER BY name ASC
            `
          );

      }


      return res.json({
        success: true,
        users:
          result.rows
      });

    } catch (error) {

      next(error);

    }

  }
);


/* =========================================================
   USERS - CREATE
========================================================= */

app.post(
  "/users",
  requireRole("admin"),
  async (
    req,
    res,
    next
  ) => {

    try {

      const nim =
        cleanString(
          req.body.nim
        );

      const name =
        cleanString(
          req.body.name
        );

      const password =
        String(
          req.body.password ||
          ""
        );

      const role =
        cleanString(
          req.body.role
        );


      if (!nim) {

        return res
          .status(400)
          .json({
            success: false,
            message:
              "NIM wajib diisi."
          });

      }


      if (!name) {

        return res
          .status(400)
          .json({
            success: false,
            message:
              "Nama wajib diisi."
          });

      }


      if (
        password.length < 6
      ) {

        return res
          .status(400)
          .json({
            success: false,
            message:
              "Password minimal 6 karakter."
          });

      }


      if (
        ![
          "praktikan",
          "asisten",
          "admin"
        ].includes(
          role
        )
      ) {

        return res
          .status(400)
          .json({
            success: false,
            message:
              "Role tidak valid."
          });

      }


      const existing =
        await pool.query(
          `
            SELECT id
            FROM users
            WHERE nim = $1
            LIMIT 1
          `,
          [
            nim
          ]
        );


      if (
        existing.rowCount >
        0
      ) {

        return res
          .status(409)
          .json({
            success: false,
            message:
              "NIM sudah digunakan."
          });

      }


      const passwordHash =
        await bcrypt.hash(
          password,
          12
        );


      const result =
        await pool.query(
          `
            INSERT INTO users (
              nim,
              name,
              password_hash,
              role
            )
            VALUES (
              $1,
              $2,
              $3,
              $4
            )
            RETURNING
              id,
              nim,
              name,
              role,
              created_at
          `,
          [
            nim,
            name,
            passwordHash,
            role
          ]
        );


      return res
        .status(201)
        .json({
          success: true,
          message:
            "Pengguna berhasil dibuat.",
          user:
            result.rows[0]
        });

    } catch (error) {

      next(error);

    }

  }
);


/* =========================================================
   USERS - UPDATE
========================================================= */

app.put(
  "/users/:id",
  requireRole("admin"),
  async (
    req,
    res,
    next
  ) => {

    try {

      const id =
        Number(
          req.params.id
        );

      const name =
        cleanString(
          req.body.name
        );

      const role =
        cleanString(
          req.body.role
        );


      if (
        !isPositiveInteger(
          id
        )
      ) {

        return res
          .status(400)
          .json({
            success: false,
            message:
              "ID pengguna tidak valid."
          });

      }


      if (!name) {

        return res
          .status(400)
          .json({
            success: false,
            message:
              "Nama wajib diisi."
          });

      }


      if (
        ![
          "praktikan",
          "asisten",
          "admin"
        ].includes(
          role
        )
      ) {

        return res
          .status(400)
          .json({
            success: false,
            message:
              "Role tidak valid."
          });

      }


      const result =
        await pool.query(
          `
            UPDATE users
            SET
              name = $1,
              role = $2
            WHERE id = $3

            RETURNING
              id,
              nim,
              name,
              role,
              created_at
          `,
          [
            name,
            role,
            id
          ]
        );


      if (
        result.rowCount ===
        0
      ) {

        return res
          .status(404)
          .json({
            success: false,
            message:
              "Pengguna tidak ditemukan."
          });

      }


      return res.json({
        success: true,
        message:
          "Pengguna berhasil diperbarui.",
        user:
          result.rows[0]
      });

    } catch (error) {

      next(error);

    }

  }
);


/* =========================================================
   REGISTER
========================================================= */

app.post(
  "/register",
  async (
    req,
    res,
    next
  ) => {

    try {

      const nim =
        cleanString(
          req.body.nim
        );

      const name =
        cleanString(
          req.body.name
        );

      const password =
        String(
          req.body.password ||
          ""
        );


      if (!nim) {

        return res
          .status(400)
          .json({
            success: false,
            message:
              "NIM wajib diisi."
          });

      }


      if (!name) {

        return res
          .status(400)
          .json({
            success: false,
            message:
              "Nama wajib diisi."
          });

      }


      if (
        password.length < 6
      ) {

        return res
          .status(400)
          .json({
            success: false,
            message:
              "Password minimal 6 karakter."
          });

      }


      const existing =
        await pool.query(
          `
            SELECT id
            FROM users
            WHERE nim = $1
            LIMIT 1
          `,
          [
            nim
          ]
        );


      if (
        existing.rowCount >
        0
      ) {

        return res
          .status(409)
          .json({
            success: false,
            message:
              "NIM sudah terdaftar."
          });

      }


      const passwordHash =
        await bcrypt.hash(
          password,
          12
        );


      const result =
        await pool.query(
          `
            INSERT INTO users (
              nim,
              name,
              password_hash,
              role
            )
            VALUES (
              $1,
              $2,
              $3,
              'praktikan'
            )

            RETURNING
              id,
              nim,
              name,
              role,
              created_at
          `,
          [
            nim,
            name,
            passwordHash
          ]
        );


      return res
        .status(201)
        .json({
          success: true,
          message:
            "Registrasi berhasil.",
          user:
            result.rows[0]
        });

    } catch (error) {

      next(error);

    }

  }
);


/* =========================================================
   LOGIN
========================================================= */

app.post(
  "/login",
  async (
    req,
    res,
    next
  ) => {

    try {

      const nim =
        cleanString(
          req.body.nim
        );

      const password =
        String(
          req.body.password ||
          ""
        );


      if (
        !nim ||
        !password
      ) {

        return res
          .status(400)
          .json({
            success: false,
            message:
              "NIM dan password wajib diisi."
          });

      }


      const result =
        await pool.query(
          `
            SELECT
              id,
              nim,
              name,
              password_hash,
              role
            FROM users
            WHERE nim = $1
            LIMIT 1
          `,
          [
            nim
          ]
        );


      if (
        result.rowCount ===
        0
      ) {

        return res
          .status(401)
          .json({
            success: false,
            message:
              "NIM atau password salah."
          });

      }


      const user =
        result.rows[0];


      const passwordValid =
        await bcrypt.compare(
          password,
          user.password_hash
        );


      if (!passwordValid) {

        return res
          .status(401)
          .json({
            success: false,
            message:
              "NIM atau password salah."
          });

      }


      req.session.regenerate(
        error => {

          if (error) {
            return next(error);
          }


          req.session.userId =
            user.id;


          req.session.user =
            {
              id:
                user.id,

              nim:
                user.nim,

              name:
                user.name,

              role:
                user.role
            };


          req.session.save(
            saveError => {

              if (saveError) {
                return next(
                  saveError
                );
              }


              let redirectUrl =
                "/";


              if (
                user.role ===
                "praktikan"
              ) {

                redirectUrl =
                  "/dashboard.html";

              } else if (
                user.role ===
                "asisten"
              ) {

                redirectUrl =
                  "/asisten.html";

              } else if (
                user.role ===
                "admin"
              ) {

                redirectUrl =
                  "/admin.html";

              }


              return res.json({
                success: true,
                message:
                  "Login berhasil.",
                user: {
                  id:
                    user.id,

                  nim:
                    user.nim,

                  name:
                    user.name,

                  role:
                    user.role
                },
                redirectUrl
              });

            }
          );

        }
      );

    } catch (error) {

      next(error);

    }

  }
);

/* =========================================================
   CHANGE PASSWORD
   SEMUA ROLE
========================================================= */

app.put(
  "/change-password",
  requireLogin,
  async (
    req,
    res,
    next
  ) => {

    try {

      const currentPassword =
        String(
          req.body.current_password ||
          ""
        );

      const newPassword =
        String(
          req.body.new_password ||
          ""
        );

      const confirmPassword =
        String(
          req.body.confirm_password ||
          ""
        );


      /* =========================
         VALIDASI
      ========================== */

      if (
        !currentPassword ||
        !newPassword ||
        !confirmPassword
      ) {

        return res
          .status(400)
          .json({
            success: false,
            message:
              "Semua kolom password wajib diisi."
          });

      }


      if (
        newPassword.length < 8
      ) {

        return res
          .status(400)
          .json({
            success: false,
            message:
              "Password baru minimal 8 karakter."
          });

      }


      if (
        newPassword !==
        confirmPassword
      ) {

        return res
          .status(400)
          .json({
            success: false,
            message:
              "Konfirmasi password tidak sama."
          });

      }


      if (
        currentPassword ===
        newPassword
      ) {

        return res
          .status(400)
          .json({
            success: false,
            message:
              "Password baru harus berbeda dari password lama."
          });

      }


      /* =========================
         AMBIL PASSWORD LAMA
      ========================== */

      const result =
        await pool.query(
          `
            SELECT
              id,
              password_hash
            FROM users
            WHERE id = $1
            LIMIT 1
          `,
          [
            req.user.id
          ]
        );


      if (
        result.rowCount ===
        0
      ) {

        return res
          .status(404)
          .json({
            success: false,
            message:
              "Pengguna tidak ditemukan."
          });

      }


      const user =
        result.rows[0];


      /* =========================
         CEK PASSWORD LAMA
      ========================== */

      const passwordValid =
        await bcrypt.compare(
          currentPassword,
          user.password_hash
        );


      if (!passwordValid) {

        return res
          .status(401)
          .json({
            success: false,
            message:
              "Password lama salah."
          });

      }


      /* =========================
         HASH PASSWORD BARU
      ========================== */

      const newPasswordHash =
        await bcrypt.hash(
          newPassword,
          12
        );


      /* =========================
         UPDATE
      ========================== */

      await pool.query(
        `
          UPDATE users

          SET
            password_hash = $1

          WHERE id = $2
        `,
        [
          newPasswordHash,
          req.user.id
        ]
      );


      return res.json({
        success: true,
        message:
          "Password berhasil diubah."
      });

    } catch (error) {

      next(error);

    }

  }
);

/* =========================================================
   PRACTICALS - GET
========================================================= */

app.get(
  "/practicals",
  requireLogin,
  async (
    req,
    res,
    next
  ) => {

    try {

      const result =
        await pool.query(
          `
            SELECT
              id,
              name,
              description,
              created_at
            FROM practicals
            ORDER BY id ASC
          `
        );


      return res.json({
        success: true,
        practicals:
          result.rows
      });

    } catch (error) {

      next(error);

    }

  }
);


/* =========================================================
   PRACTICALS - CREATE
========================================================= */

app.post(
  "/practicals",
  requireRole("admin"),
  async (
    req,
    res,
    next
  ) => {

    try {

      const name =
        cleanString(
          req.body.name
        );

      const description =
        cleanString(
          req.body.description
        );


      if (!name) {

        return res
          .status(400)
          .json({
            success: false,
            message:
              "Nama praktikum wajib diisi."
          });

      }


      const result =
        await pool.query(
          `
            INSERT INTO practicals (
              name,
              description
            )

            VALUES (
              $1,
              $2
            )

            RETURNING
              id,
              name,
              description,
              created_at
          `,
          [
            name,
            description
          ]
        );


      return res
        .status(201)
        .json({
          success: true,
          message:
            "Praktikum berhasil ditambahkan.",
          practical:
            result.rows[0]
        });

    } catch (error) {

      next(error);

    }

  }
);


/* =========================================================
   CHAPTERS - GET
========================================================= */

app.get(
  "/chapters",
  requireLogin,
  async (
    req,
    res,
    next
  ) => {

    try {

      const result =
        await pool.query(
          `
            SELECT
              c.id,
              c.practical_id,
              p.name AS practical_name,
              c.name,
              c.description,
              c.created_at

            FROM chapters c

            INNER JOIN practicals p
              ON p.id =
                c.practical_id

            ORDER BY
              c.practical_id ASC,
              c.id ASC
          `
        );


      return res.json({
        success: true,
        chapters:
          result.rows
      });

    } catch (error) {

      next(error);

    }

  }
);


/* =========================================================
   CHAPTERS - CREATE
========================================================= */

app.post(
  "/chapters",
  requireRole("admin"),
  async (
    req,
    res,
    next
  ) => {

    try {

      const practicalId =
        Number(
          req.body.practical_id
        );

      const name =
        cleanString(
          req.body.name
        );

      const description =
        cleanString(
          req.body.description
        );


      if (
        !isPositiveInteger(
          practicalId
        )
      ) {

        return res
          .status(400)
          .json({
            success: false,
            message:
              "Praktikum tidak valid."
          });

      }


      if (!name) {

        return res
          .status(400)
          .json({
            success: false,
            message:
              "Nama BAB wajib diisi."
          });

      }


      const practical =
        await pool.query(
          `
            SELECT id
            FROM practicals
            WHERE id = $1
            LIMIT 1
          `,
          [
            practicalId
          ]
        );


      if (
        practical.rowCount ===
        0
      ) {

        return res
          .status(404)
          .json({
            success: false,
            message:
              "Praktikum tidak ditemukan."
          });

      }


      const result =
        await pool.query(
          `
            INSERT INTO chapters (
              practical_id,
              name,
              description
            )

            VALUES (
              $1,
              $2,
              $3
            )

            RETURNING
              id,
              practical_id,
              name,
              description,
              created_at
          `,
          [
            practicalId,
            name,
            description
          ]
        );


      return res
        .status(201)
        .json({
          success: true,
          message:
            "BAB berhasil ditambahkan.",
          chapter:
            result.rows[0]
        });

    } catch (error) {

      next(error);

    }

  }
);


/* =========================================================
   CHAPTERS - UPDATE
========================================================= */

app.put(
  "/chapters/:id",
  requireRole("admin"),
  async (
    req,
    res,
    next
  ) => {

    try {

      const id =
        Number(
          req.params.id
        );

      const practicalId =
        Number(
          req.body.practical_id
        );

      const name =
        cleanString(
          req.body.name
        );

      const description =
        cleanString(
          req.body.description
        );


      if (
        !isPositiveInteger(id)
      ) {

        return res
          .status(400)
          .json({
            success: false,
            message:
              "ID BAB tidak valid."
          });

      }


      if (
        !isPositiveInteger(
          practicalId
        )
      ) {

        return res
          .status(400)
          .json({
            success: false,
            message:
              "Praktikum tidak valid."
          });

      }


      if (!name) {

        return res
          .status(400)
          .json({
            success: false,
            message:
              "Nama BAB wajib diisi."
          });

      }


      const practical =
        await pool.query(
          `
            SELECT id
            FROM practicals
            WHERE id = $1
            LIMIT 1
          `,
          [
            practicalId
          ]
        );


      if (
        practical.rowCount ===
        0
      ) {

        return res
          .status(404)
          .json({
            success: false,
            message:
              "Praktikum tidak ditemukan."
          });

      }


      const result =
        await pool.query(
          `
            UPDATE chapters

            SET
              practical_id = $1,
              name = $2,
              description = $3

            WHERE id = $4

            RETURNING
              id,
              practical_id,
              name,
              description,
              created_at
          `,
          [
            practicalId,
            name,
            description,
            id
          ]
        );


      if (
        result.rowCount ===
        0
      ) {

        return res
          .status(404)
          .json({
            success: false,
            message:
              "BAB tidak ditemukan."
          });

      }


      return res.json({
        success: true,
        message:
          "BAB berhasil diperbarui.",
        chapter:
          result.rows[0]
      });

    } catch (error) {

      next(error);

    }

  }
);


/* =========================================================
   CHAPTERS - DELETE
========================================================= */

app.delete(
  "/chapters/:id",
  requireRole("admin"),
  async (
    req,
    res,
    next
  ) => {

    try {

      const id =
        Number(
          req.params.id
        );


      if (
        !isPositiveInteger(id)
      ) {

        return res
          .status(400)
          .json({
            success: false,
            message:
              "ID BAB tidak valid."
          });

      }


      const result =
        await pool.query(
          `
            DELETE FROM chapters
            WHERE id = $1
            RETURNING id
          `,
          [
            id
          ]
        );


      if (
        result.rowCount ===
        0
      ) {

        return res
          .status(404)
          .json({
            success: false,
            message:
              "BAB tidak ditemukan."
          });

      }


      return res.json({
        success: true,
        message:
          "BAB berhasil dihapus."
      });

    } catch (error) {

      if (
        error.code ===
        "23503"
      ) {

        return res
          .status(409)
          .json({
            success: false,
            message:
              "BAB tidak dapat dihapus karena sudah digunakan oleh konsultasi."
          });

      }

      next(error);

    }

  }
);


/* =========================================================
   ASSISTANT PRACTICALS - GET
========================================================= */

app.get(
  "/assistant-practicals",
  requireLogin,
  async (
    req,
    res,
    next
  ) => {

    try {

      const result =
        await pool.query(
          `
            SELECT
              ap.id,
              ap.assistant_id,
              ap.practical_id,
              u.nim AS assistant_nim,
              u.name AS assistant_name,
              p.name AS practical_name,
              ap.created_at

            FROM assistant_practicals ap

            INNER JOIN users u
              ON u.id =
                ap.assistant_id

            INNER JOIN practicals p
              ON p.id =
                ap.practical_id

            ORDER BY
              ap.id ASC
          `
        );


      return res.json({
        success: true,
        assistantPracticals:
          result.rows
      });

    } catch (error) {

      next(error);

    }

  }
);


/* =========================================================
   ASSISTANT PRACTICALS - CREATE
========================================================= */

app.post(
  "/assistant-practicals",
  requireRole("admin"),
  async (
    req,
    res,
    next
  ) => {

    try {

      const assistantId =
        Number(
          req.body.assistant_id
        );

      const practicalId =
        Number(
          req.body.practical_id
        );


      if (
        !isPositiveInteger(
          assistantId
        ) ||
        !isPositiveInteger(
          practicalId
        )
      ) {

        return res
          .status(400)
          .json({
            success: false,
            message:
              "Asisten atau Praktikum tidak valid."
          });

      }


      const assistant =
        await pool.query(
          `
            SELECT
              id,
              role
            FROM users
            WHERE id = $1
            LIMIT 1
          `,
          [
            assistantId
          ]
        );


      if (
        assistant.rowCount ===
          0 ||
        assistant.rows[0].role !==
          "asisten"
      ) {

        return res
          .status(400)
          .json({
            success: false,
            message:
              "User yang dipilih bukan Asisten."
          });

      }


      const practical =
        await pool.query(
          `
            SELECT id
            FROM practicals
            WHERE id = $1
            LIMIT 1
          `,
          [
            practicalId
          ]
        );


      if (
        practical.rowCount ===
        0
      ) {

        return res
          .status(404)
          .json({
            success: false,
            message:
              "Praktikum tidak ditemukan."
          });

      }


      try {

        const result =
          await pool.query(
            `
              INSERT INTO assistant_practicals (
                assistant_id,
                practical_id
              )

              VALUES (
                $1,
                $2
              )

              RETURNING *
            `,
            [
              assistantId,
              practicalId
            ]
          );


        return res
          .status(201)
          .json({
            success: true,
            message:
              "Asisten berhasil ditugaskan.",
            assignment:
              result.rows[0]
          });

      } catch (error) {

        if (
          error.code ===
          "23505"
        ) {

          return res
            .status(409)
            .json({
              success: false,
              message:
                "Penugasan Asisten untuk Praktikum tersebut sudah ada."
            });

        }

        throw error;

      }

    } catch (error) {

      next(error);

    }

  }
);


/* =========================================================
   ASSISTANT PRACTICALS - UPDATE
========================================================= */

app.put(
  "/assistant-practicals/:id",
  requireRole("admin"),
  async (
    req,
    res,
    next
  ) => {

    try {

      const id =
        Number(
          req.params.id
        );

      const assistantId =
        Number(
          req.body.assistant_id
        );

      const practicalId =
        Number(
          req.body.practical_id
        );


      if (
        !isPositiveInteger(id)
      ) {

        return res
          .status(400)
          .json({
            success: false,
            message:
              "ID penugasan tidak valid."
          });

      }


      if (
        !isPositiveInteger(
          assistantId
        ) ||
        !isPositiveInteger(
          practicalId
        )
      ) {

        return res
          .status(400)
          .json({
            success: false,
            message:
              "Asisten atau Praktikum tidak valid."
          });

      }


      const assistant =
        await pool.query(
          `
            SELECT
              id,
              role
            FROM users
            WHERE id = $1
            LIMIT 1
          `,
          [
            assistantId
          ]
        );


      if (
        assistant.rowCount ===
          0 ||
        assistant.rows[0].role !==
          "asisten"
      ) {

        return res
          .status(400)
          .json({
            success: false,
            message:
              "User yang dipilih bukan Asisten."
          });

      }


      const practical =
        await pool.query(
          `
            SELECT id
            FROM practicals
            WHERE id = $1
            LIMIT 1
          `,
          [
            practicalId
          ]
        );


      if (
        practical.rowCount ===
        0
      ) {

        return res
          .status(404)
          .json({
            success: false,
            message:
              "Praktikum tidak ditemukan."
          });

      }


      try {

        const result =
          await pool.query(
            `
              UPDATE assistant_practicals

              SET
                assistant_id = $1,
                practical_id = $2

              WHERE id = $3

              RETURNING *
            `,
            [
              assistantId,
              practicalId,
              id
            ]
          );


        if (
          result.rowCount ===
          0
        ) {

          return res
            .status(404)
            .json({
              success: false,
              message:
                "Penugasan tidak ditemukan."
            });

        }


        return res.json({
          success: true,
          message:
            "Penugasan berhasil diperbarui.",
          assignment:
            result.rows[0]
        });

      } catch (error) {

        if (
          error.code ===
          "23505"
        ) {

          return res
            .status(409)
            .json({
              success: false,
              message:
                "Penugasan yang sama sudah ada."
            });

        }

        throw error;

      }

    } catch (error) {

      next(error);

    }

  }
);


/* =========================================================
   ASSISTANT PRACTICALS - DELETE
========================================================= */

app.delete(
  "/assistant-practicals/:id",
  requireRole("admin"),
  async (
    req,
    res,
    next
  ) => {

    try {

      const id =
        Number(
          req.params.id
        );


      if (
        !isPositiveInteger(id)
      ) {

        return res
          .status(400)
          .json({
            success: false,
            message:
              "ID penugasan tidak valid."
          });

      }


      const result =
        await pool.query(
          `
            DELETE FROM assistant_practicals
            WHERE id = $1
            RETURNING id
          `,
          [
            id
          ]
        );


      if (
        result.rowCount ===
        0
      ) {

        return res
          .status(404)
          .json({
            success: false,
            message:
              "Penugasan tidak ditemukan."
          });

      }


      return res.json({
        success: true,
        message:
          "Penugasan berhasil dihapus."
      });

    } catch (error) {

      if (
        error.code ===
        "23503"
      ) {

        return res
          .status(409)
          .json({
            success: false,
            message:
              "Penugasan tidak dapat dihapus karena sudah digunakan oleh konsultasi."
          });

      }

      next(error);

    }

  }
);


/* =========================================================
   CONSULTATIONS - GET
========================================================= */

app.get(
  "/consultations",
  requireLogin,
  async (
    req,
    res,
    next
  ) => {

    try {

      let query = `
        SELECT
          c.id,

          c.praktikan_id,
          praktikan.nim AS praktikan_nim,
          praktikan.name AS praktikan_name,

          c.assistant_id,
          assistant.nim AS assistant_nim,
          assistant.name AS assistant_name,

          c.practical_id,
          p.name AS practical_name,

          c.chapter_id,
          ch.name AS chapter_name,

          c.report_section,
          c.topic,
          c.question,
          c.file_name,

          c.consultation_date,
          c.start_time,
          c.end_time,
          c.duration_minutes,

          c.status,
          c.rejection_reason,
          c.notes,

          c.created_at,
          c.updated_at

        FROM consultations c

        INNER JOIN users praktikan
          ON praktikan.id =
            c.praktikan_id

        INNER JOIN users assistant
          ON assistant.id =
            c.assistant_id

        INNER JOIN practicals p
          ON p.id =
            c.practical_id

        INNER JOIN chapters ch
          ON ch.id =
            c.chapter_id
      `;


      const params = [];


      if (
        req.user.role ===
        "praktikan"
      ) {

        params.push(
          req.user.id
        );

        query += `
          WHERE c.praktikan_id =
            $${params.length}
        `;

      } else if (
        req.user.role ===
        "asisten"
      ) {

        params.push(
          req.user.id
        );

        query += `
          WHERE c.assistant_id =
            $${params.length}
        `;

      }


      query += `
        ORDER BY
          c.consultation_date ASC,
          c.start_time ASC,
          c.id ASC
      `;


      const result =
        await pool.query(
          query,
          params
        );


      return res.json({
        success: true,
        consultations:
          result.rows
      });

    } catch (error) {

      next(error);

    }

  }
);


/* =========================================================
   CREATE CONSULTATION
   PRAKTIKAN ONLY
========================================================= */

app.post(
  "/consultations",
  requireRole("praktikan"),
  uploadReport,
  async (
    req,
    res,
    next
  ) => {

    let client = null;


    try {

      const user =
        req.user;


      const assistantId =
        Number(
          req.body.assistant_id
        );

      const practicalId =
        Number(
          req.body.practical_id
        );

      const chapterId =
        Number(
          req.body.chapter_id
        );

      const reportSection =
        cleanString(
          req.body.report_section
        );

      const topic =
        cleanString(
          req.body.topic
        );

      const question =
        cleanString(
          req.body.question
        );

      const consultationDate =
        cleanString(
          req.body.consultation_date
        );

      const startTime =
        cleanString(
          req.body.start_time
        );

      const endTime =
        cleanString(
          req.body.end_time
        );

      const durationMinutes =
        Number(
          req.body.duration_minutes ||
          60
        );


      /* =========================
         VALIDASI
      ========================== */

      if (
        !isPositiveInteger(
          assistantId
        )
      ) {

        throw new Error(
          "Asisten tidak valid."
        );

      }


      if (
        !isPositiveInteger(
          practicalId
        )
      ) {

        throw new Error(
          "Praktikum tidak valid."
        );

      }


      if (
        !isPositiveInteger(
          chapterId
        )
      ) {

        throw new Error(
          "BAB tidak valid."
        );

      }


      if (!reportSection) {

        throw new Error(
          "Bagian laporan wajib dipilih."
        );

      }


      if (!topic) {

        throw new Error(
          "Topik konsultasi wajib diisi."
        );

      }


      if (!question) {

        throw new Error(
          "Pertanyaan atau masalah wajib diisi."
        );

      }


      if (
        !isValidDateString(
          consultationDate
        )
      ) {

        throw new Error(
          "Tanggal konsultasi tidak valid."
        );

      }


      if (
        !isValidTimeString(
          startTime
        ) ||
        !isValidTimeString(
          endTime
        )
      ) {

        throw new Error(
          "Jam konsultasi tidak valid."
        );

      }


      if (
        !Number.isInteger(
          durationMinutes
        ) ||
        durationMinutes <= 0
      ) {

        throw new Error(
          "Durasi konsultasi tidak valid."
        );

      }


      if (
        endTime <= startTime
      ) {

        throw new Error(
          "Jam selesai harus lebih besar dari jam mulai."
        );

      }


      /* =========================
         CEK ASISTEN
      ========================== */

      const assistantResult =
        await pool.query(
          `
            SELECT
              id,
              role
            FROM users
            WHERE id = $1
              AND role = 'asisten'
            LIMIT 1
          `,
          [
            assistantId
          ]
        );


      if (
        assistantResult.rowCount ===
        0
      ) {

        throw new Error(
          "Asisten tidak ditemukan."
        );

      }


      /* =========================
         CEK PRAKTIKUM
      ========================== */

      const practicalResult =
        await pool.query(
          `
            SELECT id
            FROM practicals
            WHERE id = $1
            LIMIT 1
          `,
          [
            practicalId
          ]
        );


      if (
        practicalResult.rowCount ===
        0
      ) {

        throw new Error(
          "Praktikum tidak ditemukan."
        );

      }


      /* =========================
         CEK BAB
      ========================== */

      const chapterResult =
        await pool.query(
          `
            SELECT
              id
            FROM chapters
            WHERE id = $1
              AND practical_id = $2
            LIMIT 1
          `,
          [
            chapterId,
            practicalId
          ]
        );


      if (
        chapterResult.rowCount ===
        0
      ) {

        throw new Error(
          "BAB tidak sesuai dengan Praktikum."
        );

      }


      /* =========================
         CEK PENUGASAN ASISTEN
      ========================== */

      const assignmentResult =
        await pool.query(
          `
            SELECT
              id
            FROM assistant_practicals
            WHERE assistant_id = $1
              AND practical_id = $2
            LIMIT 1
          `,
          [
            assistantId,
            practicalId
          ]
        );


      if (
        assignmentResult.rowCount ===
        0
      ) {

        throw new Error(
          "Asisten tersebut belum ditugaskan untuk Praktikum ini."
        );

      }


      /* =========================
         TRANSACTION
      ========================== */

      client =
        await pool.connect();


      await client.query(
        "BEGIN"
      );


      /* =========================
         LOCK ASISTEN + TANGGAL
      ========================== */

      await client.query(
        `
          SELECT pg_advisory_xact_lock(
            hashtext($1)
          )
        `,
        [
          `${assistantId}:${consultationDate}`
        ]
      );


      /* =========================
         CEK KONFLIK JADWAL

         PENTING:
         Hanya 4 parameter:
         $1 = assistantId
         $2 = tanggal
         $3 = jam mulai
         $4 = jam selesai
      ========================== */

      const conflictResult =
        await client.query(
          `
            SELECT
              id

            FROM consultations

            WHERE assistant_id = $1

              AND consultation_date = $2

              AND status IN (
                'pending',
                'approved'
              )

              AND start_time < $4::time
              AND end_time > $3::time

            LIMIT 1
          `,
          [
            assistantId,
            consultationDate,
            startTime,
            endTime
          ]
        );


      if (
        conflictResult.rowCount >
        0
      ) {

        await client.query(
          "ROLLBACK"
        );


        client.release();
        client = null;


        if (req.file) {

          await fs.promises
            .unlink(
              req.file.path
            )
            .catch(
              () => {}
            );

        }


        return res
          .status(409)
          .json({
            success: false,
            message:
              "Jadwal Asisten sudah memiliki konsultasi pada waktu tersebut."
          });

      }


      /* =========================
         FILE
      ========================== */

      let storedFileName =
        null;


      if (req.file) {

        storedFileName =
          req.file.filename;

      }


      /* =========================
         INSERT
      ========================== */

      const insertResult =
        await client.query(
          `
            INSERT INTO consultations (

              praktikan_id,
              assistant_id,
              practical_id,
              chapter_id,

              report_section,
              topic,
              question,
              file_name,

              consultation_date,
              start_time,
              end_time,

              duration_minutes,
              status

            )

            VALUES (

              $1,
              $2,
              $3,
              $4,

              $5,
              $6,
              $7,
              $8,

              $9,
              $10,
              $11,

              $12,
              'pending'

            )

            RETURNING *
          `,
          [
            user.id,
            assistantId,
            practicalId,
            chapterId,

            reportSection,
            topic,
            question,
            storedFileName,

            consultationDate,
            startTime,
            endTime,

            durationMinutes
          ]
        );


      await client.query(
        "COMMIT"
      );


      client.release();
      client = null;


      return res
        .status(201)
        .json({
          success: true,
          message:
            "Booking berhasil dibuat dan sedang menunggu persetujuan asisten.",
          consultation:
            insertResult.rows[0]
        });


    } catch (error) {

      if (client) {

        await client.query(
          "ROLLBACK"
        ).catch(
          () => {}
        );


        client.release();
        client = null;

      }


      if (req.file) {

        await fs.promises
          .unlink(
            req.file.path
          )
          .catch(
            () => {}
          );

      }


      console.error(
        "================================"
      );

      console.error(
        "CREATE CONSULTATION ERROR"
      );

      console.error(
        "MESSAGE:",
        error.message
      );

      console.error(
        "CODE:",
        error.code
      );

      console.error(
        "DETAIL:",
        error.detail
      );

      console.error(
        "HINT:",
        error.hint
      );

      console.error(
        "STACK:",
        error.stack
      );

      console.error(
        "================================"
      );


      return res
        .status(400)
        .json({
          success: false,
          message:
            error.message ||
            "Booking konsultasi gagal."
        });

    }

  }
);


/* =========================================================
   UPDATE CONSULTATION STATUS
========================================================= */

app.put(
  "/consultations/:id/status",
  requireRole(
    "asisten",
    "admin"
  ),
  async (
    req,
    res,
    next
  ) => {

    try {

      const consultationId =
        Number(
          req.params.id
        );

      const status =
        cleanString(
          req.body.status
        );

      const rejectionReason =
        cleanString(
          req.body.rejection_reason
        );


      if (
        !isPositiveInteger(
          consultationId
        )
      ) {

        return res
          .status(400)
          .json({
            success: false,
            message:
              "ID konsultasi tidak valid."
          });

      }


      if (
        ![
          "approved",
          "rejected"
        ].includes(
          status
        )
      ) {

        return res
          .status(400)
          .json({
            success: false,
            message:
              "Status hanya boleh approved atau rejected."
          });

      }


      const result =
        await pool.query(
          `
            SELECT
              *
            FROM consultations
            WHERE id = $1
            LIMIT 1
          `,
          [
            consultationId
          ]
        );


      if (
        result.rowCount ===
        0
      ) {

        return res
          .status(404)
          .json({
            success: false,
            message:
              "Konsultasi tidak ditemukan."
          });

      }


      const consultation =
        result.rows[0];


      if (
        req.user.role ===
          "asisten" &&
        Number(
          consultation.assistant_id
        ) !==
          Number(
            req.user.id
          )
      ) {

        return res
          .status(403)
          .json({
            success: false,
            message:
              "Kamu hanya dapat memproses konsultasi milikmu."
          });

      }


      if (
        consultation.status !==
        "pending"
      ) {

        return res
          .status(409)
          .json({
            success: false,
            message:
              "Hanya konsultasi dengan status Menunggu yang dapat diproses."
          });

      }


      if (
        status === "rejected" &&
        !rejectionReason
      ) {

        return res
          .status(400)
          .json({
            success: false,
            message:
              "Alasan penolakan wajib diisi."
          });

      }


      if (
        status === "approved"
      ) {

        const conflictResult =
          await pool.query(
            `
              SELECT
                id
              FROM consultations

              WHERE assistant_id = $1
                AND consultation_date = $2
                AND id <> $3
                AND status = 'approved'

                AND start_time < $5::time
                AND end_time > $4::time

              LIMIT 1
            `,
            [
              consultation.assistant_id,
              consultation.consultation_date,
              consultation.id,
              consultation.start_time,
              consultation.end_time
            ]
          );


        if (
          conflictResult.rowCount >
          0
        ) {

          return res
            .status(409)
            .json({
              success: false,
              message:
                "Konsultasi tidak dapat disetujui karena jadwal Asisten bertabrakan."
            });

        }

      }


      const updateResult =
        await pool.query(
          `
            UPDATE consultations

            SET
              status = $1,
              rejection_reason = $2,
              updated_at =
                CURRENT_TIMESTAMP

            WHERE id = $3

            RETURNING *
          `,
          [
            status,
            status ===
              "rejected"
              ? rejectionReason
              : null,
            consultationId
          ]
        );


      return res.json({
        success: true,
        message:
          status === "approved"
            ? "Konsultasi berhasil disetujui."
            : "Konsultasi berhasil ditolak.",
        consultation:
          updateResult.rows[0]
      });

    } catch (error) {

      next(error);

    }

  }
);


/* =========================================================
   NOTES
========================================================= */

app.put(
  "/consultations/:id/notes",
  requireRole(
    "asisten",
    "admin"
  ),
  async (
    req,
    res,
    next
  ) => {

    try {

      const consultationId =
        Number(
          req.params.id
        );

      const notes =
        cleanString(
          req.body.notes
        );


      if (
        !isPositiveInteger(
          consultationId
        )
      ) {

        return res
          .status(400)
          .json({
            success: false,
            message:
              "ID konsultasi tidak valid."
          });

      }


      const result =
        await pool.query(
          `
            SELECT
              id,
              assistant_id,
              status
            FROM consultations
            WHERE id = $1
            LIMIT 1
          `,
          [
            consultationId
          ]
        );


      if (
        result.rowCount ===
        0
      ) {

        return res
          .status(404)
          .json({
            success: false,
            message:
              "Konsultasi tidak ditemukan."
          });

      }


      const consultation =
        result.rows[0];


      if (
        req.user.role ===
          "asisten" &&
        Number(
          consultation.assistant_id
        ) !==
          Number(
            req.user.id
          )
      ) {

        return res
          .status(403)
          .json({
            success: false,
            message:
              "Kamu hanya dapat mengubah catatan konsultasi milikmu."
          });

      }


      if (
        ![
          "approved",
          "completed"
        ].includes(
          consultation.status
        )
      ) {

        return res
          .status(409)
          .json({
            success: false,
            message:
              "Catatan hanya dapat diubah pada konsultasi yang sudah disetujui atau selesai."
          });

      }


      const updateResult =
        await pool.query(
          `
            UPDATE consultations

            SET
              notes = $1,
              updated_at =
                CURRENT_TIMESTAMP

            WHERE id = $2

            RETURNING *
          `,
          [
            notes || null,
            consultationId
          ]
        );


      return res.json({
        success: true,
        message:
          "Catatan berhasil disimpan.",
        consultation:
          updateResult.rows[0]
      });

    } catch (error) {

      next(error);

    }

  }
);


/* =========================================================
   COMPLETE CONSULTATION
========================================================= */

app.put(
  "/consultations/:id/complete",
  requireRole(
    "asisten",
    "admin"
  ),
  async (
    req,
    res,
    next
  ) => {

    try {

      const consultationId =
        Number(
          req.params.id
        );


      if (
        !isPositiveInteger(
          consultationId
        )
      ) {

        return res
          .status(400)
          .json({
            success: false,
            message:
              "ID konsultasi tidak valid."
          });

      }


      const result =
        await pool.query(
          `
            SELECT
              id,
              assistant_id,
              status
            FROM consultations
            WHERE id = $1
            LIMIT 1
          `,
          [
            consultationId
          ]
        );


      if (
        result.rowCount ===
        0
      ) {

        return res
          .status(404)
          .json({
            success: false,
            message:
              "Konsultasi tidak ditemukan."
          });

      }


      const consultation =
        result.rows[0];


      if (
        req.user.role ===
          "asisten" &&
        Number(
          consultation.assistant_id
        ) !==
          Number(
            req.user.id
          )
      ) {

        return res
          .status(403)
          .json({
            success: false,
            message:
              "Kamu hanya dapat menyelesaikan konsultasi milikmu."
          });

      }


      if (
        consultation.status !==
        "approved"
      ) {

        return res
          .status(409)
          .json({
            success: false,
            message:
              "Hanya konsultasi yang sudah disetujui yang dapat ditandai selesai."
          });

      }


      const updateResult =
        await pool.query(
          `
            UPDATE consultations

            SET
              status = 'completed',
              updated_at =
                CURRENT_TIMESTAMP

            WHERE id = $1

            RETURNING *
          `,
          [
            consultationId
          ]
        );


      return res.json({
        success: true,
        message:
          "Konsultasi berhasil ditandai selesai.",
        consultation:
          updateResult.rows[0]
      });

    } catch (error) {

      next(error);

    }

  }
);


/* =========================================================
   CANCEL CONSULTATION
========================================================= */

app.put(
  "/consultations/:id/cancel",
  requireRole(
    "praktikan",
    "admin"
  ),
  async (
    req,
    res,
    next
  ) => {

    try {

      const consultationId =
        Number(
          req.params.id
        );


      if (
        !isPositiveInteger(
          consultationId
        )
      ) {

        return res
          .status(400)
          .json({
            success: false,
            message:
              "ID konsultasi tidak valid."
          });

      }


      const result =
        await pool.query(
          `
            SELECT
              id,
              praktikan_id,
              status
            FROM consultations
            WHERE id = $1
            LIMIT 1
          `,
          [
            consultationId
          ]
        );


      if (
        result.rowCount ===
        0
      ) {

        return res
          .status(404)
          .json({
            success: false,
            message:
              "Konsultasi tidak ditemukan."
          });

      }


      const consultation =
        result.rows[0];


      if (
        req.user.role ===
          "praktikan" &&
        Number(
          consultation.praktikan_id
        ) !==
          Number(
            req.user.id
          )
      ) {

        return res
          .status(403)
          .json({
            success: false,
            message:
              "Kamu hanya dapat membatalkan konsultasimu sendiri."
          });

      }


      if (
        ![
          "pending",
          "approved"
        ].includes(
          consultation.status
        )
      ) {

        return res
          .status(409)
          .json({
            success: false,
            message:
              "Konsultasi ini tidak dapat dibatalkan."
          });

      }


      const updateResult =
        await pool.query(
          `
            UPDATE consultations

            SET
              status = 'cancelled',
              updated_at =
                CURRENT_TIMESTAMP

            WHERE id = $1

            RETURNING *
          `,
          [
            consultationId
          ]
        );


      return res.json({
        success: true,
        message:
          "Konsultasi berhasil dibatalkan.",
        consultation:
          updateResult.rows[0]
      });

    } catch (error) {

      next(error);

    }

  }
);


/* =========================================================
   ACCESS CONSULTATION FILE
========================================================= */

app.get(
  "/consultations/:id/file",
  requireLogin,
  async (
    req,
    res,
    next
  ) => {

    try {

      const consultationId =
        Number(
          req.params.id
        );


      if (
        !isPositiveInteger(
          consultationId
        )
      ) {

        return res
          .status(400)
          .json({
            success: false,
            message:
              "ID konsultasi tidak valid."
          });

      }


      const result =
        await pool.query(
          `
            SELECT
              id,
              praktikan_id,
              assistant_id,
              file_name
            FROM consultations
            WHERE id = $1
            LIMIT 1
          `,
          [
            consultationId
          ]
        );


      if (
        result.rowCount ===
        0
      ) {

        return res
          .status(404)
          .json({
            success: false,
            message:
              "Konsultasi tidak ditemukan."
          });

      }


      const consultation =
        result.rows[0];


      const allowed =
        req.user.role ===
          "admin" ||
        Number(
          req.user.id
        ) ===
          Number(
            consultation.praktikan_id
          ) ||
        Number(
          req.user.id
        ) ===
          Number(
            consultation.assistant_id
          );


      if (!allowed) {

        return res
          .status(403)
          .json({
            success: false,
            message:
              "Kamu tidak memiliki akses ke file ini."
          });

      }


      if (
        !consultation.file_name
      ) {

        return res
          .status(404)
          .json({
            success: false,
            message:
              "Konsultasi ini tidak memiliki file."
          });

      }


      const storedFileName =
        path.basename(
          consultation.file_name
        );


      const filePath =
        path.join(
          uploadDir,
          storedFileName
        );


      if (
        !fs.existsSync(
          filePath
        )
      ) {

        return res
          .status(404)
          .json({
            success: false,
            message:
              "File tidak ditemukan di server."
          });

      }


      return res.download(
        filePath,
        storedFileName,
        error => {

          if (
            error &&
            !res.headersSent
          ) {

            console.error(
              "FILE DOWNLOAD ERROR:",
              error
            );

          }

        }
      );

    } catch (error) {

      next(error);

    }

  }
);


/* =========================================================
   ROUTE NOT FOUND
========================================================= */

app.use(
  (req, res) => {

    res
      .status(404)
      .json({
        success: false,
        message:
          "Endpoint tidak ditemukan."
      });

  }
);


/* =========================================================
   GLOBAL ERROR HANDLER
========================================================= */

app.use(
  (
    error,
    req,
    res,
    next
  ) => {

    console.error(
      "GLOBAL SERVER ERROR:",
      error
    );


    if (
      res.headersSent
    ) {

      return next(error);

    }


    return res
      .status(500)
      .json({
        success: false,
        message:
          isProduction
            ? "Terjadi kesalahan pada server."
            : (
                error.message ||
                "Terjadi kesalahan pada server."
              )
      });

  }
);


/* =========================================================
   START SERVER
========================================================= */

app.listen(
  PORT,
  () => {

    console.log(
      `LABCONSULT server berjalan di http://localhost:${PORT}`
    );

    console.log(
      `Environment: ${
        isProduction
          ? "production"
          : "development"
      }`
    );

    console.log(
      "Session store: PostgreSQL"
    );

    console.log(
      `Upload directory: ${uploadDir}`
    );

  }
);