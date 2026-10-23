from flask import (
    Flask, render_template, redirect, request, flash,
    url_for, session, send_from_directory, send_file, jsonify
)
import calendar
import fdb
import os
from datetime import date, datetime, timedelta
from fpdf import FPDF
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config["SECRET_KEY"] = "1234"

host = "localhost"
database = r"C:\Users\Aluno\Desktop\T.I\CredMais-Linkad-o-main\BANCO.FDB"
user = "SYSDBA"
password = "sysdba"


def conectar_banco():
    return fdb.connect(
        host=host,
        database=database,
        user=user,
        password=password
    )


def validar_senha(senha):
    if len(senha) < 8:
        return False

    tem_maiuscula = any(c.isupper() for c in senha)
    tem_minuscula = any(c.islower() for c in senha)
    tem_numero = any(c.isdigit() for c in senha)
    tem_especial = any(not c.isalnum() for c in senha)

    return tem_maiuscula and tem_minuscula and tem_numero and tem_especial


# ============================================================
# INÍCIO
# ============================================================

@app.route("/")
def inicio():
    return render_template("index.html")


@app.route("/logo")
def logo():
    return send_from_directory(
        os.path.join(app.root_path, "static", "uploads"),
        "logo.png"
    )


@app.route("/fundo")
def fundo():
    return send_from_directory(
        os.path.join(app.root_path, "static", "uploads"),
        "fundo.png"
    )


# ============================================================
# CADASTRO
# ============================================================

@app.route("/cadastro", methods=["GET", "POST"])
def cadastro():
    if request.method == "POST":
        nome = request.form.get("nome", "").strip()
        email = request.form.get("email", "").strip().lower()
        senha = request.form.get("senha", "")
        confirmar_senha = request.form.get("confirmar_senha", "")

        if not nome or not email or not senha or not confirmar_senha:
            flash("Preencha todos os campos.")
            return render_template("cadastro_usuario.html")

        if not validar_senha(senha):
            flash(
                "A senha deve ter no mínimo 8 caracteres, "
                "uma letra maiúscula, uma letra minúscula, "
                "um número e um caractere especial."
            )
            return render_template("cadastro_usuario.html")

        if senha != confirmar_senha:
            flash("As senhas não são iguais.")
            return render_template("cadastro_usuario.html")

        conexao = None
        cursor = None

        try:
            conexao = conectar_banco()
            cursor = conexao.cursor()

            cursor.execute(
                "SELECT ID_USUARIO FROM USUARIO WHERE EMAIL = ?",
                (email,)
            )

            if cursor.fetchone():
                flash("Este e-mail já está cadastrado.")
                return render_template("cadastro_usuario.html")

            senha_criptografada = generate_password_hash(senha)

            cursor.execute(
                """
                INSERT INTO USUARIO
                (
                    NOME, EMAIL, SENHA, TIPO,
                    ATIVO, TENTATIVAS_LOGIN, BLOQUEADO
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (nome, email, senha_criptografada, 1, True, 0, False)
            )

            cursor.execute(
                "SELECT ID_USUARIO FROM USUARIO WHERE EMAIL = ?",
                (email,)
            )

            usuario = cursor.fetchone()

            if not usuario:
                raise Exception(
                    "Usuário não foi encontrado após o cadastro."
                )

            id_usuario = usuario[0]

            cursor.execute(
                """
                INSERT INTO HISTORICO_SENHA
                    (SENHA, ID_USUARIO, DATA_ALTERACAO)
                VALUES (?, ?, CURRENT_TIMESTAMP)
                """,
                (senha_criptografada, id_usuario)
            )

            conexao.commit()

            flash("Cadastro realizado com sucesso!", "sucesso")
            return redirect(url_for("login"))

        except Exception:
            if conexao:
                conexao.rollback()

            app.logger.exception("Erro ao salvar cadastro.")
            flash("Erro ao salvar o cadastro.")
            return render_template("cadastro_usuario.html")

        finally:
            if cursor:
                cursor.close()
            if conexao:
                conexao.close()

    return render_template("cadastro_usuario.html")


# ============================================================
# LOGIN
# ============================================================

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        senha = request.form.get("senha", "")

        if not email or not senha:
            flash("Preencha o e-mail e a senha.")
            return render_template("login.html")

        conexao = None
        cursor = None

        try:
            conexao = conectar_banco()
            cursor = conexao.cursor()

            cursor.execute(
                """
                SELECT
                    ID_USUARIO, NOME, EMAIL, SENHA, TIPO,
                    ATIVO, TENTATIVAS_LOGIN, BLOQUEADO
                FROM USUARIO
                WHERE EMAIL = ?
                """,
                (email,)
            )

            usuario = cursor.fetchone()

            if not usuario:
                flash("E-mail ou senha incorretos.")
                return render_template("login.html")

            id_usuario = usuario[0]
            nome_usuario = usuario[1]
            email_usuario = usuario[2]
            senha_banco = usuario[3]
            tipo_usuario = usuario[4]
            ativo = usuario[5]
            tentativas_login = int(usuario[6] or 0)
            bloqueado = usuario[7]

            if ativo is False or ativo == 0:
                flash("Sua conta está inativa. Não é possível realizar o login.")
                return render_template("login.html")

            if bloqueado is True or bloqueado == 1:
                flash("Sua conta está bloqueada por excesso de tentativas.")
                return render_template("login.html")

            if not senha_banco:
                flash("Este usuário não possui uma senha cadastrada.")
                return render_template("login.html")

            if not check_password_hash(senha_banco, senha):
                tentativas_login += 1

                if tentativas_login >= 3:
                    cursor.execute(
                        """
                        UPDATE USUARIO
                        SET TENTATIVAS_LOGIN = ?, BLOQUEADO = ?
                        WHERE ID_USUARIO = ?
                        """,
                        (tentativas_login, True, id_usuario)
                    )
                    conexao.commit()

                    flash(
                        "Você atingiu o limite de 3 tentativas. "
                        "Sua conta foi bloqueada."
                    )
                    return render_template("login.html")

                cursor.execute(
                    """
                    UPDATE USUARIO
                    SET TENTATIVAS_LOGIN = ?
                    WHERE ID_USUARIO = ?
                    """,
                    (tentativas_login, id_usuario)
                )
                conexao.commit()

                restantes = 3 - tentativas_login

                if restantes == 1:
                    flash(
                        "E-mail ou senha incorretos. Você tem "
                        "apenas 1 tentativa restante."
                    )
                else:
                    flash(
                        f"E-mail ou senha incorretos. "
                        f"Você ainda possui {restantes} tentativas."
                    )

                return render_template("login.html")

            cursor.execute(
                """
                UPDATE USUARIO
                SET TENTATIVAS_LOGIN = ?, BLOQUEADO = ?
                WHERE ID_USUARIO = ?
                """,
                (0, False, id_usuario)
            )
            conexao.commit()

            session.clear()
            session["usuario_id"] = id_usuario
            session["usuario_nome"] = nome_usuario
            session["usuario_email"] = email_usuario
            session["usuario_tipo"] = tipo_usuario

            return redirect(url_for("dashboard"))

        except Exception:
            app.logger.exception("Erro no login.")
            flash("Erro ao realizar o login.")
            return render_template("login.html")

        finally:
            if cursor:
                cursor.close()
            if conexao:
                conexao.close()

    return render_template("login.html")


@app.route("/sucesso")
def sucesso():
    if "usuario_id" not in session:
        return redirect(url_for("inicio"))

    return redirect(url_for("dashboard"))


@app.route("/sistema")
def sistema():
    if "usuario_id" not in session:
        return redirect(url_for("inicio"))

    return redirect(url_for("dashboard"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("inicio"))


@app.route("/sair")
def sair():
    caminho = os.path.join(app.root_path, "static", "uploads")
    return send_from_directory(caminho, "sair.png")


# ============================================================
# PERFIL
# ============================================================

def buscar_usuario(id_usuario):
    conexao = conectar_banco()

    try:
        cursor = conexao.cursor()
        try:
            cursor.execute(
                """
                SELECT ID_USUARIO, NOME, EMAIL, SENHA
                FROM USUARIO
                WHERE ID_USUARIO = ?
                """,
                (id_usuario,)
            )
            return cursor.fetchone()
        finally:
            cursor.close()
    finally:
        conexao.close()


def email_ja_existe(email, id_usuario):
    conexao = conectar_banco()

    try:
        cursor = conexao.cursor()
        try:
            cursor.execute(
                """
                SELECT ID_USUARIO
                FROM USUARIO
                WHERE EMAIL = ? AND ID_USUARIO <> ?
                """,
                (email, id_usuario)
            )
            return cursor.fetchone() is not None
        finally:
            cursor.close()
    finally:
        conexao.close()


def buscar_ultimas_senhas(id_usuario):
    conexao = conectar_banco()

    try:
        cursor = conexao.cursor()
        try:
            cursor.execute(
                """
                SELECT FIRST 3 SENHA
                FROM HISTORICO_SENHA
                WHERE ID_USUARIO = ?
                ORDER BY DATA_ALTERACAO DESC, ID_HISTORICO_SENHA DESC
                """,
                (id_usuario,)
            )
            return [registro[0] for registro in cursor.fetchall()]
        finally:
            cursor.close()
    finally:
        conexao.close()


@app.route("/perfil", methods=["GET", "POST"])
def perfil():
    if "usuario_id" not in session:
        flash("Faça login para acessar seu perfil.")
        return redirect(url_for("login"))

    id_usuario = session["usuario_id"]

    if request.method == "GET":
        try:
            usuario = buscar_usuario(id_usuario)
        except Exception:
            app.logger.exception("Erro ao consultar perfil.")
            flash("Não foi possível conectar ao banco de dados.", "erro")
            return render_template(
                "editar_perfil.html", nome="", email=""
            )

        if usuario is None:
            flash("Usuário não encontrado.", "erro")
            return render_template(
                "editar_perfil.html", nome="", email=""
            )

        return render_template(
            "editar_perfil.html",
            nome=usuario[1] or "",
            email=usuario[2] or ""
        )

    nome = request.form.get("nome", "").strip()
    email = request.form.get("email", "").strip().lower()
    senha_atual = request.form.get("senha_atual", "")
    nova_senha = request.form.get("nova_senha", "")

    if not nome or not email or not senha_atual:
        flash("Preencha nome, e-mail e senha atual.", "erro")
        return redirect(url_for("perfil"))

    if len(nome) > 100 or len(email) > 100:
        flash("Nome e e-mail devem ter no máximo 100 caracteres.", "erro")
        return redirect(url_for("perfil"))

    try:
        usuario = buscar_usuario(id_usuario)

        if usuario is None:
            flash("Usuário não encontrado.", "erro")
            return redirect(url_for("perfil"))

        hash_atual = usuario[3] or ""

        if not check_password_hash(hash_atual, senha_atual):
            flash("A senha atual está incorreta.", "erro")
            return redirect(url_for("perfil"))

        if email_ja_existe(email, id_usuario):
            flash("Este e-mail já está cadastrado.", "erro")
            return redirect(url_for("perfil"))

        novo_hash = None

        if nova_senha:
            if not validar_senha(nova_senha):
                flash(
                    "A nova senha precisa ter 8 caracteres ou mais, "
                    "uma letra maiúscula, uma minúscula, um número "
                    "e um símbolo.",
                    "erro"
                )
                return redirect(url_for("perfil"))

            senhas_anteriores = buscar_ultimas_senhas(id_usuario)

            if check_password_hash(hash_atual, nova_senha):
                flash("A nova senha deve ser diferente da senha atual.", "erro")
                return redirect(url_for("perfil"))

            for senha_antiga in senhas_anteriores:
                if check_password_hash(senha_antiga, nova_senha):
                    flash(
                        "Não é permitido reutilizar as três últimas senhas.",
                        "erro"
                    )
                    return redirect(url_for("perfil"))

            novo_hash = generate_password_hash(nova_senha)

        conexao = conectar_banco()

        try:
            cursor = conexao.cursor()

            if novo_hash is not None:
                cursor.execute(
                    """
                    INSERT INTO HISTORICO_SENHA
                        (SENHA, ID_USUARIO, DATA_ALTERACAO)
                    VALUES (?, ?, ?)
                    """,
                    (hash_atual, id_usuario, datetime.now())
                )

                cursor.execute(
                    """
                    UPDATE USUARIO
                    SET NOME = ?, EMAIL = ?, SENHA = ?
                    WHERE ID_USUARIO = ?
                    """,
                    (nome, email, novo_hash, id_usuario)
                )
            else:
                cursor.execute(
                    """
                    UPDATE USUARIO
                    SET NOME = ?, EMAIL = ?
                    WHERE ID_USUARIO = ?
                    """,
                    (nome, email, id_usuario)
                )

            conexao.commit()

        except Exception:
            conexao.rollback()
            raise

        finally:
            conexao.close()

        session["usuario_nome"] = nome
        session["usuario_email"] = email

        flash("Dados pessoais atualizados com sucesso!", "sucesso")
        return redirect(url_for("perfil"))

    except Exception:
        app.logger.exception("Erro ao atualizar o perfil.")
        flash(
            "Não foi possível salvar os dados. "
            "Confira a conexão e a estrutura do banco.",
            "erro"
        )
        return redirect(url_for("perfil"))


# ============================================================
# MOVIMENTAÇÕES
# ============================================================

TIPO_RECEITA = 1
TIPO_DESPESA = 0

PERIODOS = {
    "ultimos": "Últimos 3 Meses",
    "proximos": "Próximos 3 Meses",
    "todos": "Todo o Tempo",
}


def conectar():
    return conectar_banco()


def id_usuario_movimentacao():
    return session.get("usuario_id")


def formatar_reais(valor):
    texto = f"{float(valor):,.2f}"
    texto = texto.replace(",", "X")
    texto = texto.replace(".", ",")
    return texto.replace("X", ".")


def datas_do_periodo(periodo):
    hoje = date.today()

    if periodo == "ultimos":
        inicio = hoje - timedelta(days=90)
        fim = hoje
    elif periodo == "proximos":
        inicio = hoje
        fim = hoje + timedelta(days=90)
    else:
        inicio = date(2000, 1, 1)
        fim = date(2100, 1, 1)

    return inicio, fim


def montar_movimentacao(linha):
    if linha[3] == TIPO_RECEITA:
        categoria = "Receita"
        classe = "receita"
        sinal = "+"
    else:
        categoria = "Despesa"
        classe = "despesa"
        sinal = "-"

    classificacao = "Fixa" if linha[5] == 1 else "Variável"
    descricao = linha[2] or ""
    valor = float(linha[4])

    return {
        "id": linha[0],
        "data": linha[1].strftime("%d/%m"),
        "data_completa": linha[1].strftime("%d/%m/%Y"),
        "descricao": descricao,
        "categoria": categoria,
        "classe": classe,
        "sinal": sinal,
        "classificacao": classificacao,
        "valor": valor,
        "valor_texto": formatar_reais(valor)
    }


def buscar_movimentacoes(data_inicio, data_fim):
    con = conectar()

    try:
        cursor = con.cursor()
        try:
            cursor.execute(
                """
                SELECT
                    ID_MOV_FINANCEIRA, DATA_LANCAMENTO, DESCRICAO,
                    TIPO, VALOR, CLASSIFICACAO
                FROM MOV_FINANCEIRA
                WHERE ID_USUARIO = ?
                  AND DATA_LANCAMENTO >= ?
                  AND DATA_LANCAMENTO <= ?
                ORDER BY DATA_LANCAMENTO DESC, ID_MOV_FINANCEIRA DESC
                """,
                (id_usuario_movimentacao(), data_inicio, data_fim)
            )

            return [
                montar_movimentacao(linha)
                for linha in cursor.fetchall()
            ]
        finally:
            cursor.close()
    finally:
        con.close()


def buscar_movimentacao(id_mov):
    con = conectar()

    try:
        cursor = con.cursor()
        try:
            cursor.execute(
                """
                SELECT
                    ID_MOV_FINANCEIRA, DATA_LANCAMENTO, DESCRICAO,
                    TIPO, VALOR, CLASSIFICACAO
                FROM MOV_FINANCEIRA
                WHERE ID_MOV_FINANCEIRA = ? AND ID_USUARIO = ?
                """,
                (id_mov, id_usuario_movimentacao())
            )

            linha = cursor.fetchone()
            return montar_movimentacao(linha) if linha else None
        finally:
            cursor.close()
    finally:
        con.close()


def somar(tipo, data_inicio=date(2000, 1, 1)):
    con = conectar()

    try:
        cursor = con.cursor()
        try:
            cursor.execute(
                """
                SELECT VALOR
                FROM MOV_FINANCEIRA
                WHERE ID_USUARIO = ?
                  AND TIPO = ?
                  AND DATA_LANCAMENTO >= ?
                """,
                (id_usuario_movimentacao(), tipo, data_inicio)
            )

            return sum(float(linha[0]) for linha in cursor.fetchall())
        finally:
            cursor.close()
    finally:
        con.close()


@app.route("/movimentacoes")
def movimentacoes():
    if "usuario_id" not in session:
        flash("Faça login para acessar esta página.", "erro")
        return redirect(url_for("login"))

    periodo = request.args.get("periodo", "ultimos")

    if periodo not in PERIODOS:
        periodo = "ultimos"

    data_inicio, data_fim = datas_do_periodo(periodo)
    dados = buscar_movimentacoes(data_inicio, data_fim)

    saldo = somar(TIPO_RECEITA) - somar(TIPO_DESPESA)

    inicio_30_dias = date.today() - timedelta(days=30)
    receitas = somar(TIPO_RECEITA, inicio_30_dias)
    despesas = somar(TIPO_DESPESA, inicio_30_dias)

    return render_template(
        "movimentacoes.html",
        dados=dados,
        saldo_texto=formatar_reais(saldo),
        receitas_texto=formatar_reais(receitas),
        despesas_texto=formatar_reais(despesas),
        periodo=periodo
    )


@app.route("/nova-movimentacao", methods=["GET", "POST"])
def nova_movimentacao():
    if "usuario_id" not in session:
        flash("Faça login para acessar esta página.", "erro")
        return redirect(url_for("login"))

    if request.method == "POST":
        tipo = request.form.get("tipo", "").strip()
        categoria = request.form.get("categoria", "").strip()
        valor = request.form.get("valor", "").strip()
        classificacao = request.form.get("classificacao", "2")
        meses = request.form.get("meses", "1")

        if not tipo:
            flash("Informe o tipo de movimentação.", "erro")
            return redirect(url_for("nova_movimentacao"))

        if categoria not in ("Receita", "Despesa"): # se nao colocar a categoria da erro, não da pra cadastrar
            flash("Selecione Receita ou Despesa.", "erro")
            return redirect(url_for("nova_movimentacao"))

        try:
            valor_numerico = float(valor.replace(",", ".")) # valor numero
        except (ValueError, AttributeError):
            valor_numerico = 0

        if valor_numerico <= 0: # n coloca valor negativo, obriga o usuario a colocar valor positivo
            flash("Insira um valor válido.", "erro")
            return redirect(url_for("nova_movimentacao"))

        if classificacao == "1":
            classificacao_numero = 1

            try:
                quantidade = int(meses)
            except ValueError:
                quantidade = 0

            if quantidade < 1 or quantidade > 120:
                flash("Informe de 1 a 120 meses.", "erro")
                return redirect(url_for("nova_movimentacao"))
        else:
            classificacao_numero = 2
            quantidade = 1

        tipo_numero = (
            TIPO_RECEITA if categoria == "Receita" else TIPO_DESPESA
        )

        con = conectar()

        try:
            cursor = con.cursor()

            try:
                hoje = date.today()

                for i in range(quantidade):
                    total_meses = hoje.month - 1 + i # pega o total de meses para colocar na parcela
                    ano = hoje.year + total_meses // 12 # descobre o ano para colocar
                    mes = total_meses % 12 + 1 # descobre o mes
                    ultimo_dia = calendar.monthrange(ano, mes)[1] # pega o ultimo dia ????
                    dia = min(hoje.day, ultimo_dia) # pega o dia
                    data_mov = date(ano, mes, dia) # pega a data para colocar na movimentação

                    cursor.execute( # aqui faz o insert, insere na tabela de movimentação financeira, o tipo, valor, data, descrição, id do usuario e a classificação
                        """
                        INSERT INTO MOV_FINANCEIRA
                        (
                            TIPO, VALOR, DATA_LANCAMENTO,
                            DESCRICAO, ID_USUARIO, CLASSIFICACAO
                        )
                        VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (
                            tipo_numero,
                            valor_numerico,
                            data_mov,
                            tipo,
                            id_usuario_movimentacao(),
                            classificacao_numero
                        )
                    )

                con.commit()

            except Exception:
                con.rollback()
                raise

        finally:
            con.close()

        session["ultima_movimentacao"] = { # aqui serve para ele preencher a nova movimentação
            "valor_texto": formatar_reais(valor_numerico), # preencher o valor
            "categoria": categoria,# preencher a categoria
            "descricao": tipo, # coloca a descrição o tipo, se é receita ou despesa dando duas o
            "classe": "receita" if categoria == "Receita" else "despesa"
        }

        return redirect(url_for("movimentacao_registrada"))

    return render_template("nova_movimentacao.html")


@app.route("/movimentacao-registrada")
def movimentacao_registrada():
    dados = session.pop("ultima_movimentacao", None)

    if dados is None:
        return redirect(url_for("movimentacoes"))

    return render_template("movimentacao_registrada.html", dados=dados)


@app.route("/movimentacao/<int:id_mov>")
def visualizar_movimentacao(id_mov):
    mov = buscar_movimentacao(id_mov)

    if "usuario_id" not in session:
        flash("Faça login para acessar esta página.", "erro")
        return redirect(url_for("login"))

    if mov is None:
        flash("Movimentação não encontrada.", "erro")
        return redirect(url_for("movimentacoes"))

    return render_template("visualizar_movimentacao.html", mov=mov)


@app.route("/movimentacao/<int:id_mov>/editar", methods=["GET", "POST"])
def editar_movimentacao(id_mov):
    mov = buscar_movimentacao(id_mov)

    if mov is None:
        flash("Movimentação não encontrada.", "erro")
        return redirect(url_for("movimentacoes"))

    if request.method == "POST":
        descricao = request.form.get("descricao", "").strip()

        if not descricao:
            flash("Informe a descrição da movimentação.", "erro")
            return redirect(url_for("editar_movimentacao", id_mov=id_mov))

        if len(descricao) > 100:
            flash("A descrição pode ter no máximo 100 caracteres.", "erro")
            return redirect(url_for("editar_movimentacao", id_mov=id_mov))

        con = conectar()

        try:
            cursor = con.cursor()
            try:
                cursor.execute(
                    """
                    UPDATE MOV_FINANCEIRA
                    SET DESCRICAO = ?
                    WHERE ID_MOV_FINANCEIRA = ? AND ID_USUARIO = ?
                    """,
                    (descricao, id_mov, id_usuario_movimentacao())
                )
                con.commit()
            except Exception:
                con.rollback()
                raise
        finally:
            con.close()

        flash("Descrição atualizada com sucesso!", "sucesso")
        return redirect(
            url_for("visualizar_movimentacao", id_mov=id_mov)
        )

    return render_template("editar_movimentacao.html", mov=mov)


@app.route("/movimentacao/<int:id_mov>/excluir", methods=["POST"])
def excluir_movimentacao(id_mov):
    mov = buscar_movimentacao(id_mov)

    if mov is None:
        flash("Movimentação não encontrada.", "erro")
        return redirect(url_for("movimentacoes"))

    con = conectar()
    id_usuario = id_usuario_movimentacao()

    try:
        cursor = con.cursor()

        try:
            if mov["classificacao"] == "Fixa":
                tipo_numero = (
                    TIPO_RECEITA
                    if mov["categoria"] == "Receita"
                    else TIPO_DESPESA
                )

                cursor.execute(
                    """
                    SELECT ID_MOV_FINANCEIRA, VALOR
                    FROM MOV_FINANCEIRA
                    WHERE ID_USUARIO = ?
                      AND CLASSIFICACAO = 1
                      AND TIPO = ?
                      AND DESCRICAO = ?
                    """,
                    (id_usuario, tipo_numero, mov["descricao"])
                )

                candidatas = cursor.fetchall()
                quantidade = 0

                for candidata in candidatas:
                    if float(candidata[1]) == mov["valor"]:
                        cursor.execute(
                            """
                            DELETE FROM MOV_FINANCEIRA
                            WHERE ID_MOV_FINANCEIRA = ? AND ID_USUARIO = ?
                            """,
                            (candidata[0], id_usuario)
                        )
                        quantidade += 1

                if quantidade == 1:
                    mensagem = "Movimentação excluída com sucesso!"
                else:
                    mensagem = (
                        f"{quantidade} movimentações fixas iguais "
                        "foram excluídas com sucesso!"
                    )
            else:
                cursor.execute(
                    """
                    DELETE FROM MOV_FINANCEIRA
                    WHERE ID_MOV_FINANCEIRA = ? AND ID_USUARIO = ?
                    """,
                    (id_mov, id_usuario)
                )
                mensagem = "Movimentação excluída com sucesso!"

            con.commit()

        except Exception:
            con.rollback()
            raise

    finally:
        con.close()

    flash(mensagem, "sucesso")
    return redirect(url_for("movimentacoes"))


# ============================================================
# RELATÓRIO PDF
# ============================================================

def texto_pdf(texto):
    texto = str(texto).encode("latin-1", "replace")
    return texto.decode("latin-1")


@app.route("/relatorio", methods=["GET"])
def relatorio():
    periodo = request.args.get("periodo", "ultimos")

    if periodo not in PERIODOS:
        periodo = "ultimos"

    data_inicio, data_fim = datas_do_periodo(periodo)
    movimentacoes_pdf = buscar_movimentacoes(data_inicio, data_fim)

    if not movimentacoes_pdf:
        return jsonify({
            "erro": "Nenhuma movimentação encontrada no período."
        }), 404

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    pdf.set_font("Arial", style="B", size=16)
    pdf.cell(
        190, 10,
        texto_pdf("Relatório de Movimentações - CredMais"),
        ln=True,
        align="C"
    )

    pdf.set_font("Arial", size=10)
    pdf.cell(
        190, 8,
        texto_pdf(
            f"Período: {PERIODOS[periodo]} | "
            f"Gerado em: {datetime.now().strftime('%d/%m/%Y %H:%M')}"
        ),
        ln=True,
        align="C"
    )

    pdf.ln(5)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(5)

    pdf.set_font("Arial", style="B", size=10)
    pdf.cell(30, 10, "Data", border=1)
    pdf.cell(75, 10, texto_pdf("Descrição"), border=1)
    pdf.cell(35, 10, "Categoria", border=1)
    pdf.cell(50, 10, texto_pdf("Valor (R$)"), border=1, ln=True)

    pdf.set_font("Arial", size=9)
    total_receitas = 0
    total_despesas = 0

    for item in movimentacoes_pdf:
        if item["categoria"] == "Receita":
            total_receitas += item["valor"]
            sinal = "+"
        else:
            total_despesas += item["valor"]
            sinal = "-"

        pdf.cell(30, 10, item["data_completa"], border=1)
        pdf.cell(75, 10, texto_pdf(item["descricao"])[:38], border=1)
        pdf.cell(35, 10, texto_pdf(item["categoria"]), border=1)
        pdf.cell(
            50, 10,
            texto_pdf(f"{sinal} R$ {formatar_reais(item['valor'])}"),
            border=1,
            ln=True
        )

    pdf.ln(10)
    pdf.set_font("Arial", style="B", size=11)
    pdf.cell(
        190, 10,
        f"Total de movimentacoes: {len(movimentacoes_pdf)}",
        ln=True,
        align="C"
    )
    pdf.cell(
        190, 10,
        texto_pdf(f"Receitas: R$ {formatar_reais(total_receitas)}"),
        ln=True,
        align="C"
    )
    pdf.cell(
        190, 10,
        texto_pdf(f"Despesas: R$ {formatar_reais(total_despesas)}"),
        ln=True,
        align="C"
    )
    pdf.cell(
        190, 10,
        texto_pdf(
            f"Saldo do período: R$ "
            f"{formatar_reais(total_receitas - total_despesas)}"
        ),
        ln=True,
        align="C"
    )

    pdf_path = os.path.join(
        app.root_path, "relatorio_movimentacoes.pdf"
    )
    pdf.output(pdf_path)

    return send_file(
        pdf_path,
        as_attachment=True,
        mimetype="application/pdf"
    )


# ============================================================
# TAXAS DE JUROS — FIREBIRD
#
# Estrutura utilizada:
# TAXA_JUROS
#   ID_TAXA_JUROS
#   DATA_REFERENCIA
#   TAXA_MENSAL
#
# O ano do formulário é armazenado em DATA_REFERENCIA
# usando o primeiro dia daquele ano.
# ============================================================

def converter_taxa(linha):
    """
    Converte o registro do Firebird para um dicionário
    utilizado pelas páginas HTML.
    """
    data_referencia = linha[1]

    if isinstance(data_referencia, datetime):
        data_referencia = data_referencia.date()

    return {
        "id": linha[0],
        "id_taxa_juros": linha[0],
        "data_referencia": data_referencia,
        "ano": data_referencia.year,
        "juros": float(linha[2]),
        "taxa_mensal": float(linha[2])
    }


def buscar_taxas_banco():
    """
    Busca todas as taxas cadastradas no banco.
    """
    conexao = conectar_banco()

    try:
        cursor = conexao.cursor()

        try:
            cursor.execute(
                """
                SELECT ID_TAXA_JUROS, DATA_REFERENCIA, TAXA_MENSAL
                FROM TAXA_JUROS
                ORDER BY DATA_REFERENCIA DESC, ID_TAXA_JUROS DESC
                """
            )

            return [
                converter_taxa(linha)
                for linha in cursor.fetchall()
            ]

        finally:
            cursor.close()

    finally:
        conexao.close()


def buscar_taxa_por_ano(ano):
    """
    Procura a taxa correspondente ao ano informado.
    """
    conexao = conectar_banco()

    try:
        cursor = conexao.cursor()

        try:
            cursor.execute(
                """
                SELECT FIRST 1
                    ID_TAXA_JUROS, DATA_REFERENCIA, TAXA_MENSAL
                FROM TAXA_JUROS
                WHERE EXTRACT(YEAR FROM DATA_REFERENCIA) = ?
                ORDER BY ID_TAXA_JUROS DESC
                """,
                (ano,)
            )

            linha = cursor.fetchone()

            if linha is None:
                return None

            return converter_taxa(linha)

        finally:
            cursor.close()

    finally:
        conexao.close()


def buscar_taxa_por_id(id_taxa):
    """
    Procura uma taxa pelo identificador.
    """
    conexao = conectar_banco()

    try:
        cursor = conexao.cursor()

        try:
            cursor.execute(
                """
                SELECT ID_TAXA_JUROS, DATA_REFERENCIA, TAXA_MENSAL
                FROM TAXA_JUROS
                WHERE ID_TAXA_JUROS = ?
                """,
                (id_taxa,)
            )

            linha = cursor.fetchone()

            if linha is None:
                return None

            return converter_taxa(linha)

        finally:
            cursor.close()

    finally:
        conexao.close()


def validar_dados_taxa(ano_texto, juros_texto):
    """
    Valida o ano e a taxa recebidos dos formulários.
    Aceita taxas decimais usando vírgula ou ponto.
    """
    try:
        ano = int(ano_texto)
        juros = float(juros_texto.strip().replace(",", "."))

    except (ValueError, TypeError, AttributeError):
        raise ValueError("Informe um ano e uma taxa válidos.")

    if ano < 1900 or ano > 9999:
        raise ValueError("Informe um ano válido.")

    if juros < 0:
        raise ValueError("A taxa de juros não pode ser negativa.")

    return ano, juros


@app.route("/taxas/editar", methods=["GET", "POST"])
def editar_taxa():

    if "usuario_id" not in session:
        flash("Faça login para acessar esta página.", "erro")
        return redirect(url_for("login"))
    if request.method == "POST":
        ano_texto = request.form.get("ano", "").strip()
        juros_texto = request.form.get("juros", "").strip()

        try:
            ano, juros = validar_dados_taxa(
                ano_texto, juros_texto
            )

            taxa_existente = buscar_taxa_por_ano(ano)

            if taxa_existente is None:
                flash(
                    "Não existe uma taxa cadastrada para esse ano.",
                    "erro"
                )
                return redirect(url_for("editar_taxa"))

            conexao = conectar_banco()

            try:
                cursor = conexao.cursor()

                cursor.execute(
                    """
                    UPDATE TAXA_JUROS
                    SET TAXA_MENSAL = ?
                    WHERE ID_TAXA_JUROS = ?
                    """,
                    (juros, taxa_existente["id"])
                )

                conexao.commit()
                cursor.close()

            finally:
                conexao.close()

            flash("Taxa atualizada com sucesso!", "sucesso")
            return redirect(url_for("editar_taxa", ano=ano))

        except ValueError as erro:
            flash(str(erro), "erro")
            return redirect(url_for("editar_taxa"))

        except Exception:
            app.logger.exception("Erro ao editar taxa.")
            flash("Não foi possível salvar as alterações.", "erro")
            return redirect(url_for("editar_taxa"))

    ano_texto = request.args.get("ano", "").strip() #carregar a taxa quando abrir a página

    try:
        if ano_texto:
            taxa = buscar_taxa_por_ano(int(ano_texto))
        else:
            taxas = buscar_taxas_banco()
            taxa = taxas[0] if taxas else {"ano": "", "juros": ""}

    except ValueError:
        taxa = {"ano": "", "juros": ""}
        flash("O ano informado é inválido.", "erro")

    except Exception:
        app.logger.exception("Erro ao carregar taxa para edição.")
        taxa = {"ano": "", "juros": ""}
        flash("Não foi possível carregar as taxas do banco.", "erro")

    if taxa is None:
        taxa = {"ano": "", "juros": ""}
        flash("Não foi encontrada uma taxa para esse ano.", "erro")

    return render_template("editar_taxas.html", taxa=taxa)

    # Permite preencher o formulário com o ano enviado na URL:
    # /taxas/editar?ano=2026
    ano_texto = request.args.get("ano", "").strip()

    try:
        if ano_texto:
            taxa = buscar_taxa_por_ano(int(ano_texto))
        else:
            taxas = buscar_taxas_banco()
            taxa = taxas[0] if taxas else {"ano": "", "juros": ""}

    except ValueError:
        taxa = {"ano": "", "juros": ""}
        flash("O ano informado é inválido.", "erro")

    except Exception:
        app.logger.exception("Erro ao carregar taxa para edição.")
        taxa = {"ano": "", "juros": ""}
        flash("Não foi possível carregar as taxas do banco.", "erro")

    if taxa is None:
        taxa = {"ano": "", "juros": ""}
        flash("Não foi encontrada uma taxa para esse ano.", "erro")

    return render_template("editar_taxas.html", taxa=taxa)


@app.route("/taxas/cadastrar", methods=["GET", "POST"])
def cadastrar_taxa():
    taxa = {"ano": "", "juros": ""}
    if "usuario_id" not in session:
        flash("Faça login para acessar esta página.", "erro")
        return redirect(url_for("login"))

    if request.method == "POST":
        ano_texto = request.form.get("ano", "").strip()
        juros_texto = request.form.get("juros", "").strip()

        taxa = {
            "ano": ano_texto,
            "juros": juros_texto
        }

        try:
            ano, juros = validar_dados_taxa(
                ano_texto, juros_texto
            )

            taxa_existente = buscar_taxa_por_ano(ano)

            if taxa_existente is not None:
                flash(
                    f"Já existe uma taxa cadastrada para o ano {ano}.",
                    "erro"
                )
                return render_template(
                    "cadastrar_taxas.html", taxa=taxa
                )

            data_referencia = date(ano, 1, 1)
            conexao = conectar_banco()

            try:
                cursor = conexao.cursor()

                try:
                    cursor.execute(
                        """
                        INSERT INTO TAXA_JUROS
                            (DATA_REFERENCIA, TAXA_MENSAL)
                        VALUES (?, ?)
                        """,
                        (data_referencia, juros)
                    )

                    conexao.commit()

                except Exception:
                    conexao.rollback()
                    raise

                finally:
                    cursor.close()

            finally:
                conexao.close()

            flash("Taxa cadastrada com sucesso!", "sucesso")
            return redirect(url_for("cadastrar_taxa"))

        except ValueError as erro:
            flash(str(erro), "erro")
            return render_template(
                "cadastrar_taxas.html", taxa=taxa
            )

        except Exception:
            app.logger.exception("Erro ao cadastrar taxa.")
            flash(
                "Não foi possível cadastrar a taxa no banco de dados.",
                "erro"
            )
            return render_template(
                "cadastrar_taxas.html", taxa=taxa
            )

    return render_template("cadastrar_taxas.html", taxa=taxa)


@app.route("/taxas")
def listar_taxas():
    try:
        taxas = buscar_taxas_banco()

    except Exception:
        app.logger.exception("Erro ao listar taxas.")
        flash("Não foi possível consultar as taxas no banco.", "erro")
        taxas = []

    return render_template("listar_taxas.html", taxas=taxas)


@app.route("/taxas/administrar")
def administrar_taxas():
    try:
        taxas = buscar_taxas_banco()

    except Exception:
        app.logger.exception("Erro ao carregar administração de taxas.")
        flash("Não foi possível consultar as taxas no banco.", "erro")
        taxas = []

    return render_template(
        "administrar_taxas.html",
        taxas=taxas
    )


# Rotas de imagens utilizadas nas páginas de taxas.

@app.route("/logo_taxas")
def logo_taxas():
    caminho = os.path.join(app.root_path, "static", "uploads")
    return send_from_directory(caminho, "logo_taxas.png")


@app.route("/icone_taxas")
def icone_taxas():
    caminho = os.path.join(app.root_path, "static", "uploads")
    return send_from_directory(caminho, "icone_taxas.png")


# ============================================================
# DASHBOARD
# ============================================================


# ============================================================
# DASHBOARD
# ============================================================


@app.route("/dashboard")
def dashboard():
    if "usuario_id" not in session:
        return redirect(url_for("login"))

    # Pega a data atual
    hoje = date.today()

    # Transforma a data no formato dia/mês/ano
    data_atual = hoje.strftime("%d/%m/%Y")

    # Soma todas as receitas do usuário
    receita_total = somar(TIPO_RECEITA)

    # Soma todas as despesas do usuário
    despesa_total = somar(TIPO_DESPESA)

    # Calcula as receitas menos as despesas
    renda_mensal_liquida = receita_total - despesa_total

    # Envia os valores para o HTML
    return render_template(
        "dashboard.html",
        data_atual=data_atual,
        renda_mensal_liquida=formatar_reais(renda_mensal_liquida),
        receita_total=formatar_reais(receita_total),
        despesa_total=formatar_reais(despesa_total)
    )



@app.route("/logo_dashboard")
def logo_dashboard():
    caminho = os.path.join(app.root_path, "static", "uploads")
    return send_from_directory(caminho, "logo_dashboard.png")


@app.route("/dinheiro")
def dinheiro():
    caminho = os.path.join(app.root_path, "static", "uploads")
    return send_from_directory(caminho, "dinheiro.png")


@app.route("/check")
def check():
    caminho = os.path.join(app.root_path, "static", "uploads")
    return send_from_directory(caminho, "check.png")


@app.route("/quadrado")
def quadrado():
    caminho = os.path.join(app.root_path, "static", "uploads")
    return send_from_directory(caminho, "quadrado.png")


@app.route("/calculadora")
def calculadora():
    caminho = os.path.join(app.root_path, "static", "uploads")
    return send_from_directory(caminho, "calculadora.png")


@app.route("/escudo")
def escudo():
    caminho = os.path.join(app.root_path, "static", "uploads")
    return send_from_directory(caminho, "escudo.png")


@app.route("/predio")
def predio():
    caminho = os.path.join(app.root_path, "static", "uploads")
    return send_from_directory(caminho, "predio.png")


# ============================================================
# EXECUÇÃO
# ============================================================

if __name__ == "__main__":
    app.run(debug=True)