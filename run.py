from app import create_app

app = create_app()

if __name__ == "__main__":
    #fix
    # app.run(debug=False) 

    app.run(debug=True)