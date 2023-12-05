import os

def criar_pastas_mensais(diretorio_base):
    """Cria uma pasta para cada mês do ano no diretório especificado."""
    meses = ["01_Janeiro", "02_Fevereiro", "03_Marco", "04_Abril", "05_Maio", "06_Junho",
             "07_Julho", "08_Agosto", "09_Setembro", "10_Outubro", "11_Novembro", "12_Dezembro"]

    for mes in meses:
        caminho_completo = os.path.join(diretorio_base, mes)
        try:
            os.makedirs(caminho_completo)
            print(f"Pasta '{mes}' criada em '{diretorio_base}'.")
        except FileExistsError:
            print(f"A pasta '{mes}' já existe em '{diretorio_base}'.")

def main():
    # Note o uso de raw string aqui
    diretorio_base = input(r"Caminho onde serão criados os diretórios")
    criar_pastas_mensais(diretorio_base)

if __name__ == "__main__":
    main()
