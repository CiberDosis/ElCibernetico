

#### El Cibernetico 
##### Creado por CiberDosis
########################################################################################################################################################################################################################
########################################################################################################################################################################################################################
##########################################################################  <--- Librerias ---> ############################################################################################################ 
########################################################################################################################################################################################################################
########################################################################################################################################################################################################################


import psutil
import os
import shutil
import tkinter as tk
import tkinter.font as font
from tkinter import filedialog, messagebox, simpledialog
import subprocess
import socket
import requests
from bs4 import BeautifulSoup
import re
from tkinter import ttk
import threading



########################################################################################################################################################################################################################
########################################################################################################################################################################################################################
##########################################################################  <--- Archivos y Sistema  ---> ############################################################################################################ 
########################################################################################################################################################################################################################
########################################################################################################################################################################################################################

    
def organize_files(source_dir, destination_dir):
    if not os.path.exists(destination_dir):
        os.makedirs(destination_dir)

    for filename in os.listdir(source_dir):
        src = os.path.join(source_dir, filename)
        if os.path.isfile(src):
            file_extension = os.path.splitext(filename)[1]
            destination_folder = os.path.join(destination_dir, file_extension[1:])
            if not os.path.exists(destination_folder):
                os.makedirs(destination_folder)
            shutil.move(src, os.path.join(destination_folder, filename))


def organize_button_click():
    source_dir = source_dir_entry.get()  
    destination_dir = destination_dir_entry.get() 
    if not source_dir or not destination_dir:
        messagebox.showerror("Error", "Por favor seleccione los directorios de origen y destino.")
        return
    organize_files(source_dir, destination_dir)
    messagebox.showinfo("Éxito", "¡Archivos organizados exitosamente!")

def browse_source_directory():
    source_dir = filedialog.askdirectory()
    if source_dir:
        source_dir_entry.delete(0, tk.END)
        source_dir_entry.insert(0, source_dir)
        create_source_file_entry.delete(0, tk.END)
        create_source_file_entry.insert(0, source_dir)
        source_directory_entry.delete(0, tk.END)
        source_directory_entry.insert(0, source_dir)


def browse_directory():
    directory = filedialog.askdirectory()
    if directory:
        directory_entry.delete(0, tk.END)  # Limpiar el campo de entrada
        directory_entry.insert(0, directory)  # Insertar la ruta seleccionada en el campo de entrada
        list_directory_contents(directory)  # Llamar a la función para listar el contenido del directorio seleccionado



def browse_destination_directory():
    destination_dir = filedialog.askdirectory()
    if destination_dir:
        destination_dir_entry.delete(0, tk.END)
        destination_dir_entry.insert(0, destination_dir)



def browse_source_directory_create():
    source_dir = filedialog.askdirectory()
    if source_dir:
        create_source_file_entry.delete(0, tk.END)
        create_source_file_entry.insert(0, source_dir)







def crear_archivo():
    try:
        # Obtener la ruta del directorio del campo de entrada
        directorio = create_source_file_entry.get()
        if not directorio:
            status_text.config(state="normal")
            status_text.delete(1.0, tk.END)
            status_text.insert(tk.END, "Por favor, selecciona un directorio.")
            status_text.config(state="disabled")
            return
        # Pedir al usuario que seleccione un nombre de archivo y ubicación
        nombre_archivo = filedialog.asksaveasfilename(initialdir=directorio, title="Selecciona un directorio y nombre para el archivo")
        if nombre_archivo:
            # Crear el archivo en la ruta completa
            with open(nombre_archivo, 'w') as archivo:
                archivo.write("Contenido inicial (opcional)")

            # Mostrar el estado de la operación y la ruta del archivo creado
            status_text.config(state="normal")
            status_text.delete(1.0, tk.END)
            status_text.insert(tk.END, f"Archivo '{nombre_archivo}' creado exitosamente.")
            status_text.config(state="disabled")
            file_path_text.config(state="normal")
            file_path_text.delete(1.0, tk.END)
            file_path_text.insert(tk.END, f"Ruta: {nombre_archivo}")
            file_path_text.config(state="disabled")
            print(f"Archivo '{nombre_archivo}' creado exitosamente.")
    except Exception as e:
        # En caso de error, mostrar un mensaje de error en el cuadro de texto de estado
        status_text.config(state="normal")
        status_text.delete(1.0, tk.END)
        status_text.insert(tk.END, f"Error al crear el archivo: {e}")
        status_text.config(state="disabled")
        print(f"Error al crear el archivo: {e}")



def borrar_archivo():
    try:
        # Obtener la ruta del archivo del campo de entrada
        archivo = create_source_file_entry.get()
        if not archivo:
            status_text.config(state="normal")
            status_text.delete(1.0, tk.END)
            status_text.insert(tk.END, "Por favor, selecciona un archivo.")
            status_text.config(state="disabled")
            return
        # Borrar el archivo
        os.remove(archivo)
        # Mostrar el estado de la operación
        status_text.config(state="normal")
        status_text.delete(1.0, tk.END)
        status_text.insert(tk.END, f"Archivo '{archivo}' borrado exitosamente.")
        status_text.config(state="disabled")
        file_path_text.config(state="normal")
        file_path_text.delete(1.0, tk.END)
        file_path_text.insert(tk.END, f"Ruta: {archivo}")
        file_path_text.config(state="disabled")
        print(f"Archivo '{archivo}' borrado exitosamente.")
    except FileNotFoundError:
        # En caso de que el archivo no exista, mostrar un mensaje de error
        status_text.config(state="normal")
        status_text.delete(1.0, tk.END)
        status_text.insert(tk.END, f"El archivo '{archivo}' no existe.")
        status_text.config(state="disabled")
        print(f"El archivo '{archivo}' no existe.")
    except Exception as e:
        # En caso de error, mostrar un mensaje de error en el cuadro de texto de estado
        status_text.config(state="normal")
        status_text.delete(1.0, tk.END)
        status_text.insert(tk.END, f"Error al borrar el archivo: {e}")
        status_text.config(state="disabled")
        print(f"Error al borrar el archivo: {e}")


def crear_directorio():
    try:
        # Obtener la ruta del directorio del campo de entrada
        nombre_directorio = source_directory_entry.get()
        if not nombre_directorio:
            status_directory_text.config(state="normal")
            status_directory_text.delete(1.0, tk.END)
            status_directory_text.insert(tk.END, "Por favor, selecciona un directorio.")
            status_directory_text.config(state="disabled")
            return
        # Crear el directorio
        os.makedirs(nombre_directorio)
        # Mostrar el estado de la operación y la ruta del directorio creado
        status_directory_text.config(state="normal")
        status_directory_text.delete(1.0, tk.END)
        status_directory_text.insert(tk.END, f"Directorio '{nombre_directorio}' creado exitosamente.")
        status_directory_text.config(state="disabled")
        directory_path_text.config(state="normal")
        directory_path_text.delete(1.0, tk.END)
        directory_path_text.insert(tk.END, f"Ruta: {nombre_directorio}")
        directory_path_text.config(state="disabled")
        print(f"Directorio '{nombre_directorio}' creado exitosamente.")
    except FileExistsError:
        status_directory_text.config(state="normal")
        status_directory_text.delete(1.0, tk.END)
        status_directory_text.insert(tk.END, f"El directorio '{nombre_directorio}' ya existe.")
        status_directory_text.config(state="disabled")
        print(f"El directorio '{nombre_directorio}' ya existe.")
    except Exception as e:
        status_directory_text.config(state="normal")
        status_directory_text.delete(1.0, tk.END)
        status_directory_text.insert(tk.END, f"Error al crear el directorio '{nombre_directorio}': {e}")
        status_directory_text.config(state="disabled")
        print(f"Error al crear el directorio '{nombre_directorio}': {e}")



def borrar_directorio():
    try:
        # Obtener la ruta del directorio del campo de entrada
        nombre_directorio = source_directory_entry.get()
        if not nombre_directorio:
            status_directory_text.config(state="normal")
            status_directory_text.delete(1.0, tk.END)
            status_directory_text.insert(tk.END, "Por favor, selecciona un directorio.")
            status_directory_text.config(state="disabled")
            return
        # Borrar el directorio
        os.rmdir(nombre_directorio)
        # Mostrar el estado de la operación y la ruta del directorio borrado
        status_directory_text.config(state="normal")
        status_directory_text.delete(1.0, tk.END)
        status_directory_text.insert(tk.END, f"Directorio '{nombre_directorio}' borrado exitosamente.")
        status_directory_text.config(state="disabled")
        directory_path_text.config(state="normal")
        directory_path_text.delete(1.0, tk.END)
        directory_path_text.insert(tk.END, f"Ruta: {nombre_directorio}")
        directory_path_text.config(state="disabled")
        print(f"Directorio '{nombre_directorio}' borrado exitosamente.")
    except FileNotFoundError:
        status_directory_text.config(state="normal")
        status_directory_text.delete(1.0, tk.END)
        status_directory_text.insert(tk.END, f"El directorio '{nombre_directorio}' no existe.")
        status_directory_text.config(state="disabled")
        print(f"El directorio '{nombre_directorio}' no existe.")
    except OSError as e:
        status_directory_text.config(state="normal")
        status_directory_text.delete(1.0, tk.END)
        status_directory_text.insert(tk.END, f"Error al borrar el directorio '{nombre_directorio}': {e}")
        status_directory_text.config(state="disabled")
        print(f"Error al borrar el directorio '{nombre_directorio}': {e}")


def mirar_particiones():
    particiones = psutil.disk_partitions()
    result_textbox_particiones.config(state="normal")
    result_textbox_particiones.delete(1.0, tk.END)  # Limpiar contenido anterior
    result_textbox_particiones.insert(tk.END, "Particiones en disco:\n", "header")
    for particion in particiones:
        result_textbox_particiones.insert(tk.END, f"Disco: {particion.device}, Tipo: {particion.fstype}\n")
    result_textbox_particiones.config(state="disabled")



def porcentaje_bateria():
    try:
        bateria = psutil.sensors_battery()
        porcentaje = bateria.percent
        result_textbox_bateria.config(state="normal")
        result_textbox_bateria.delete(1.0, tk.END)  # Limpiar contenido anterior
        result_textbox_bateria.insert(tk.END, f"Porcentaje de batería:\n", "header" )
        result_textbox_bateria.insert(tk.END, f"Estado de Bateria {porcentaje}%\n")
        result_textbox_bateria.config(state="disabled")
    except AttributeError:
        result_textbox_bateria.config(state="normal")
        result_textbox_bateria.delete(1.0, tk.END)  # Limpiar contenido anterior
        result_textbox_bateria.insert(tk.END, "No se pudo obtener la información de la batería.\n")
        result_textbox_bateria.config(state="disabled")



def rename_file(source_dir, filename, new_name):
    old_path = os.path.join(source_dir, filename)
    new_path = os.path.join(source_dir, new_name)
    os.rename(old_path, new_path)
    messagebox.showinfo("Éxito", f"El archivo {filename} ha sido renombrado como {new_name}.")

def rename_files(source_dir):
    if not os.path.exists(source_dir):
        messagebox.showerror("Error", "El directorio de origen no existe.")
        return
    
    # Obtener la lista de archivos en el directorio de origen
    files = os.listdir(source_dir)
    
    # Renombrar uno o varios archivos
    for i, filename in enumerate(files, start=1):
        new_filename = f"archivo_{i}.{filename.split('.')[-1]}"
        os.rename(os.path.join(source_dir, filename), os.path.join(source_dir, new_filename))
        
    messagebox.showinfo("Éxito", "Los archivos han sido renombrados correctamente.")

def rename_files_gui():
    source_dir = rename_source_entry.get()
    if not source_dir:
        messagebox.showerror("Error", "Por favor seleccione un directorio de origen.")
        return
    
    if single_file_var.get():
        selected_file = single_file_entry.get()
        if selected_file:
            new_name = ask_new_filename(selected_file)
            if new_name:
                rename_file(source_dir, selected_file, new_name)
        else:
            messagebox.showerror("Error", "Por favor seleccione un archivo para renombrar.")
    else:
        rename_files(source_dir)

def browse_single_file():
    file_path = filedialog.askopenfilename()
    if file_path:
        single_file_entry.delete(0, tk.END)
        single_file_entry.insert(0, os.path.basename(file_path))

def ask_new_filename(filename):
    new_name = simpledialog.askstring("Nuevo Nombre", f"Ingrese el nuevo nombre para '{filename}':")
    return new_name

def browse_directory_rename():
    directory = filedialog.askdirectory()
    if directory:
        rename_source_entry.delete(0, tk.END)
        rename_source_entry.insert(0, directory)

def toggle_single_file_entry():
    if single_file_var.get():
        single_file_entry.config(state=tk.NORMAL)
        browse_file_button.config(state=tk.NORMAL)
    else:
        single_file_entry.delete(0, tk.END)
        single_file_entry.config(state=tk.DISABLED)
        browse_file_button.config(state=tk.DISABLED)


def list_directory_contents(directory):
    try:
        contents = os.listdir(directory)  # Obtener el contenido del directorio
        result_textbox_dir.config(state="normal")  # Habilitar la edición del cuadro de texto
        result_textbox_dir.delete(1.0, tk.END)  # Limpiar el contenido del cuadro de texto
        for item in contents:
            result_textbox_dir.insert(tk.END, f"{item}\n")  # Agregar cada elemento del directorio al cuadro de texto
        result_textbox_dir.config(state="disabled")  # Deshabilitar la edición del cuadro de texto
    except Exception as e:
        result_textbox_dir.config(state="normal")
        result_textbox_dir.delete(1.0, tk.END)
        result_textbox_dir.insert(tk.END, f"Error al listar el contenido del directorio: {e}")
        result_textbox_dir.config(state="disabled")


########################################################################################################################################################################################################################
########################################################################################################################################################################################################################


########################################################################################################################################################################################################################
########################################################################################################################################################################################################################
##########################################################################  <--- Ejecutar Comandos  ---> ############################################################################################################ 
########################################################################################################################################################################################################################
########################################################################################################################################################################################################################


def execute_command():
    """Ejecuta un comando utilizando subprocess."""
    command = command_entry.get()
    use_console = use_console_var.get()
    if use_console:
        subprocess.run(command, shell=True)
    else:
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, error = process.communicate()
        result_textbox_commando.config(state="normal")
        result_textbox.delete(1.0, tk.END)
        if output:
            result_textbox_commando.insert(tk.END, "Salida del comando:\n")
            result_textbox_commando.insert(tk.END, output.decode('utf-8', errors='replace'))  
        if error:
            result_textbox_commando.insert(tk.END, "\nError del comando:\n")
            result_textbox_commando.insert(tk.END, error.decode())
        result_textbox_commando.config(state="disabled")



########################################################################################################################################################################################################################
########################################################################################################################################################################################################################








########################################################################################################################################################################################################################
########################################################################################################################################################################################################################
##########################################################################  <--- Rastrear Sitio Web  ---> ############################################################################################################ 
########################################################################################################################################################################################################################
########################################################################################################################################################################################################################



def get_ip_address(domain):
    """Obtiene la dirección IP de un nombre de dominio."""
    try:
        ip_address = socket.gethostbyname(domain)
        return ip_address
    except socket.gaierror:
        return None

def get_links(url):
    """Obtiene los enlaces de una página web."""
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        links = [link.get('href') for link in soup.find_all('a')]
        return links
    except requests.RequestException as e:
        print("Error al obtener los enlaces de la página:", e)
        return []

def show_ip_and_links():
    """Muestra la dirección IP y los enlaces de la página web."""
    domain = domain_entry.get()
    if not domain:
        messagebox.showerror("Error", "Por favor ingrese un nombre de dominio.")
        return

    ip_address = get_ip_address(domain)
    if ip_address:
        ip_label.config(text=f"Dirección IP de {domain}: {ip_address}")
    else:
        ip_label.config(text=f"No se pudo resolver la dirección IP de {domain}.")

    url = f"http://{domain}"
    links = get_links(url)
    if links:
        links_text = "\n".join(links)
        links_textbox.config(state="normal")
        links_textbox.delete(1.0, tk.END)
        links_textbox.insert(tk.END, links_text)
        links_textbox.config(state="disabled")
    else:
        links_textbox.config(state="normal")
        links_textbox.delete(1.0, tk.END)
        links_textbox.insert(tk.END, "No se encontraron enlaces en la página.")
        links_textbox.config(state="disabled")




########################################################################################################################################################################################################################
########################################################################################################################################################################################################################




########################################################################################################################################################################################################################
########################################################################################################################################################################################################################
##########################################################################  <--- URL Amigable  ---> ############################################################################################################ 
########################################################################################################################################################################################################################
########################################################################################################################################################################################################################



def create_friendly_url(text):
    """Crea una URL amigable a partir del texto ingresado."""
    # Convertir texto a minúsculas
    text = text.lower()
    # Eliminar caracteres especiales, excepto guiones y espacios
    text = re.sub(r'[^\w\s-]', '', text)
    # Reemplazar espacios con guiones
    text = text.replace(' ', '-')
    # Eliminar múltiples guiones consecutivos
    text = re.sub(r'-+', '-', text)
    # Eliminar guiones al principio y al final
    text = text.strip('-')
    return text

def generate_url():
    """Genera una URL amigable y la muestra en el interfaz gráfica."""
    input_text = text_entry.get()
    if input_text:
        friendly_url = create_friendly_url(input_text)
        url_label_dos.config(text=f"URL amigable: {friendly_url}")
        url_label_dos.grid(row=2, column=0, columnspan=2, padx=10, pady=5)  # Posicionar el label dentro del frame
    else:
        url_label_dos.config(text="")  # Limpiar el texto del label si no se ingresa ningún texto
        messagebox.showerror("Error", "Por favor ingrese un texto.")


########################################################################################################################################################################################################################
########################################################################################################################################################################################################################



########################################################################################################################################################################################################################
########################################################################################################################################################################################################################
##########################################################################  <--- Monitoreo de Red  ---> ############################################################################################################ 
########################################################################################################################################################################################################################
########################################################################################################################################################################################################################



def detectar_puertos_gui():
    global result_textbox
    conexiones = psutil.net_connections()
    ports_info = "Puertos abiertos:\n"
    for conexion in conexiones:
        if conexion.laddr.port > 0:
            ports_info += f"PID: {conexion.pid}, Local Address: {conexion.laddr}, Estado: {conexion.status}\n"
    result_textbox.config(state="normal")
    result_textbox.delete(1.0, tk.END)
    result_textbox.insert(tk.END, ports_info)
    result_textbox.config(state="disabled")



def listar_procesos_activos_gui():
    global result_textbox
    processes_info = "Procesos activos:\n"
    for proceso in psutil.process_iter(['pid', 'name']):
        processes_info += f"PID: {proceso.info['pid']}, Nombre: {proceso.info['name']}\n"
    result_textbox.config(state="normal")
    result_textbox.delete(1.0, tk.END)
    result_textbox.insert(tk.END, processes_info)
    result_textbox.config(state="disabled")



def terminar_proceso_gui():
    pid = pid_entry.get()
    if not pid:
        messagebox.showerror("Error", "Por favor ingrese el PID del proceso a terminar.")
        return
    try:
        proceso = psutil.Process(int(pid))
        proceso.terminate()
        termination_result_label.config(text=f"Proceso con PID {pid} terminado correctamente.")
    except psutil.NoSuchProcess:
        termination_result_label.config(text=f"No existe un proceso con el PID {pid}.") 
    except psutil.AccessDenied:
        termination_result_label.config(text="No tienes permisos para terminar este proceso.")
    except Exception as e:
        termination_result_label.config(text=f"Ocurrió un error al intentar terminar el proceso: {e}")



def ping_host():
    host = host_entry.get()
    if not host:
        messagebox.showerror("Error", "Por favor ingrese un host para hacer ping.")
        return
    # Ejecutar el comando ping
    command = f"ping {host}"
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, error = process.communicate()
    if output:
        # Decodificar el resultado del ping
        output = output.decode("utf-8", errors="replace")
        # Mostrar el resultado del ping en el widget de texto
        result_box.config(state="normal")
        result_box.delete(1.0, tk.END)
        result_box.insert(tk.END, output)
        result_box.config(state="disabled")
    if error:
        messagebox.showerror("Error", error.decode())
  


def execute_nmap_command():
    command = nmap_command_entry.get()
    if not command:
        messagebox.showerror("Error", "Por favor ingrese un comando de Nmap.")
        return
    try:
        # Ejecutar el comando Nmap
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, error = process.communicate()
        # Decodificar la salida en utf-8
        output = output.decode("utf-8", errors="replace")
        # Mostrar el resultado del comando en el widget de texto
        nmap_result_text.config(state="normal")
        nmap_result_text.delete(1.0, tk.END)
        nmap_result_text.insert(tk.END, output)
        nmap_result_text.config(state="disabled")
        # Mostrar errores si los hay
        if error:
            messagebox.showerror("Error", error.decode())
    except Exception as e:
        messagebox.showerror("Error", f"Error al ejecutar el comando Nmap: {e}")        
  


def monitor_http_traffic(url):
    try:
        response = requests.get(url)
        if response.status_code == 200:
            result_text.config(state="normal")
            result_text.delete(1.0, tk.END)
            result_text.insert(tk.END, "La solicitud HTTP fue exitosa.\n")
            result_text.insert(tk.END, "Contenido de la página:\n")
            result_text.insert(tk.END, response.text)
            result_text.config(state="disabled")
        else:
            messagebox.showerror("Error", f"La solicitud HTTP falló. Código de estado: {response.status_code}")
    except requests.RequestException as e:
        messagebox.showerror("Error", f"Error al realizar la solicitud HTTP: {e}")



def monitor_http_traffic_gui():
    url = url_entry.get()
    if not url:
        messagebox.showerror("Error", "Por favor ingrese una URL para monitorear.")
        return
    monitor_http_traffic(url)


def monitor_bandwidth():
    try:
        # Obtener estadísticas sobre el uso de la red
        network_stats = psutil.net_io_counters()
        sent_bytes = network_stats.bytes_sent
        received_bytes = network_stats.bytes_recv
        
        # Calcular el ancho de banda
        sent_kb = sent_bytes / 1024
        received_kb = received_bytes / 1024
        
        # Mostrar los resultados en la interfaz gráfica
        bandwidth_info = f"Ancho de banda enviado: {sent_kb:.2f} KB\n"
        bandwidth_info += f"Ancho de banda recibido: {received_kb:.2f} KB\n"
        
        # Actualizar el cuadro de texto con la información del ancho de banda
        bandwidth_text.config(state="normal")
        bandwidth_text.delete(1.0, tk.END)
        bandwidth_text.insert(tk.END, bandwidth_info)
        bandwidth_text.config(state="disabled")
        
    except Exception as e:
        messagebox.showerror("Error", f"Error al monitorear el ancho de banda: {e}")
        


def obtener_info_interfaces_red():
    try:
        interfaces = psutil.net_if_addrs()
        info = "Información de interfaces de red:\n"
        for name, addrs in interfaces.items():
            info += f"Nombre: {name}\n"
            for addr in addrs:
                if addr.family == socket.AF_INET:
                    info += f"  Dirección IP: {addr.address}\n"
                    info += f"  Máscara de red: {addr.netmask}\n"
                elif addr.family == socket.AF_INET6:
                    info += f"  Dirección IPv6: {addr.address}\n"
        # Limpiar el cuadro de texto antes de mostrar los resultados
        result_textbox_interfaces.config(state="normal")
        result_textbox_interfaces.delete(1.0, tk.END)
        # Mostrar la información en el cuadro de texto
        result_textbox_interfaces.insert(tk.END, info)
        # Deshabilitar el cuadro de texto para que el usuario no pueda editar el contenido
        result_textbox_interfaces.config(state="disabled")
    except Exception as e:
        # En caso de error, mostrar un mensaje de error en el cuadro de texto
        result_textbox_interfaces.config(state="normal")
        result_textbox_interfaces.delete(1.0, tk.END)
        result_textbox_interfaces.insert(tk.END, f"Error al obtener información de interfaces de red: {e}")
        result_textbox_interfaces.config(state="disabled")


def netstat_op():
    # Limpiar el cuadro de texto antes de mostrar el resultado
    resultado_text.delete("1.0", tk.END)
    
    try:
        # Ejecutar el comando de netstat según la opción seleccionada
        opcion = opcion_netstat.get()
        command = ""
        if opcion == "Muestra todas las conexiones, tanto activas como inactivas.":
            command = "netstat -a"
        elif opcion == "Muestra solo las conexiones TCP.":
            command = "netstat -t"
        elif opcion == "Muestra solo las conexiones UDP.":
            command = "netstat -u"
        elif opcion == "Muestra el nombre del programa que está utilizando cada puerto.":
            command = "netstat -p"
        elif opcion == "Muestra la tabla de enrutamiento.":
            command = "netstat -r"
        
        # Ejecutar el comando y obtener la salida
        output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
   

        # Insertar el resultado en el cuadro de texto
        resultado_text.insert(tk.END, output.decode("utf-8", errors="ignore"))
    except subprocess.CalledProcessError as e:
        # Mostrar mensaje de error si ocurre un error al ejecutar el comando
        resultado_text.insert(tk.END, f"Error: {e.output.decode('utf-8', errors='ignore')}")
    finally:
        # Desactivar el cuadro de texto después de mostrar el resultado
        resultado_text.config(state="normal")





########################################################################################################################################################################################################################
########################################################################################################################################################################################################################
########################################################################################################################################################################################################################
########################################################################################################################################################################################################################
########################################################################################################################################################################################################################
########################################################################################################################################################################################################################


def toggle_fullscreen(event=None):
    root.attributes("-fullscreen", not root.attributes("-fullscreen"))



########################################################################################################################################################################################################################
########################################################################################################################################################################################################################
##########################################################################  <--- Interfaz Grafica  ---> ############################################################################################################ 
########################################################################################################################################################################################################################
########################################################################################################################################################################################################################





# Crear la ventana principal
root = tk.Tk()
root.title("Proyecto BSD: El Cibernetico")
root.attributes('-fullscreen', True)
style = ttk.Style()
style.theme_use("classic")
root.geometry("1920x1080")
style.configure('.', background="#f0f0f0")
# Configurar la fuente global
font_style = ('Arial', 10)  # Cambia la fuente y el tamaño según tus preferencias
default_font = tk.font.nametofont("TkDefaultFont")
default_font.configure(size=font_style[1])
root.option_add("*Font", default_font)
frame_width = 600
frame_height = 400

########################################################################################################################################################################################################################
########################################################################################################################################################################################################################
##########################################################################  <--- Archivos  ---> ############################################################################################################ 
########################################################################################################################################################################################################################
########################################################################################################################################################################################################################




# Definir el atajo de teclado (por ejemplo, F11) para alternar la pantalla completa
root.bind("<F11>", toggle_fullscreen)

# También puedes usar otro atajo de teclado como Escape para salir de la pantalla completa
root.bind("<Escape>", toggle_fullscreen)




""" organize_files_frame = tk.LabelFrame(root, text="Archivos y Sistema")
organize_files_frame.grid(row=0, column=0, padx=10, pady=5, sticky="nsew")
 """
# Crear el notebook para las pestañas dentro del LabelFrame
organize_files_notebook = ttk.Notebook(root)
organize_files_notebook.grid(row=0, column=0, padx=10, pady=5, sticky="nsew")

# Crear un frame para la pestaña de organizar archivos
organize_files_frame_tab = ttk.Frame(organize_files_notebook)
organize_files_notebook.add(organize_files_frame_tab, text="Organizar Archivos")

# Agregar widgets dentro de la pestaña de organizar archivos
source_label = tk.Label(organize_files_frame_tab, text="Directorio de Origen:")
source_label.grid(row=0, column=0, padx=10, pady=5)

source_dir_entry = tk.Entry(organize_files_frame_tab, width=50)
source_dir_entry.grid(row=0, column=1, padx=10, pady=5)

source_button = tk.Button(organize_files_frame_tab, text="Examinar", command=browse_source_directory)
source_button.grid(row=0, column=2, padx=10, pady=5)

destination_label = tk.Label(organize_files_frame_tab, text="Directorio de Destino:")
destination_label.grid(row=1, column=0, padx=10, pady=5)

destination_dir_entry = tk.Entry(organize_files_frame_tab, width=50)
destination_dir_entry.grid(row=1, column=1, padx=10, pady=5)

destination_button = tk.Button(organize_files_frame_tab, text="Examinar", command=browse_destination_directory)
destination_button.grid(row=1, column=2, padx=10, pady=5)

organize_button = tk.Button(organize_files_frame_tab, text="Organizar Archivos", command=organize_button_click)
organize_button.grid(row=2, column=1, padx=10, pady=10)


# Crear un frame para la pestaña de organizar archivos
create_files_frame_tab = ttk.Frame(organize_files_notebook)
organize_files_notebook.add(create_files_frame_tab, text="Crear / Eliminar Archivos")

## Campo de entrada para la ruta del directorio
create_source_file_entry = tk.Entry(create_files_frame_tab, width=50)
create_source_file_entry.grid(row=0, column=1, padx=10, pady=5)

# Etiqueta para la selección del directorio
source_file_label = tk.Label(create_files_frame_tab, text="Selecciona un directorio:")
source_file_label.grid(row=0, column=0, padx=10, pady=5)

# Botón para examinar directorio
source_file_button = tk.Button(create_files_frame_tab, text="Examinar", command=browse_source_directory_create)
source_file_button.grid(row=0, column=2, padx=10, pady=5)

# Botón para crear archivo
create_button = tk.Button(create_files_frame_tab, text="Crear Archivo", command=crear_archivo)
create_button.grid(row=1, column=1, padx=10, pady=5)

# Botón para eliminar archivo
delete_button = tk.Button(create_files_frame_tab, text="Eliminar Archivo", command=borrar_archivo)
delete_button.grid(row=2, column=1, padx=10, pady=5)

# Cuadro de texto para mostrar el estado de la operación
status_text = tk.Text(create_files_frame_tab, width=60, height=3)
status_text.grid(row=3, column=0, columnspan=3, padx=10, pady=5)

# Cuadro de texto para mostrar la ruta del archivo
file_path_text = tk.Text(create_files_frame_tab, width=60, height=3)
file_path_text.grid(row=4, column=0, columnspan=3, padx=10, pady=5)




# Crear un frame para la pestaña de organizar archivos
create_dir_frame_tab = ttk.Frame(organize_files_notebook)
organize_files_notebook.add(create_dir_frame_tab, text="Crear / Eliminar Directorios")

# Campo de entrada para la ruta del directorio
source_directory_entry = tk.Entry(create_dir_frame_tab, width=50)
source_directory_entry.grid(row=0, column=1, padx=10, pady=5)

# Etiqueta para la selección del directorio
source_directory_label = tk.Label(create_dir_frame_tab, text="Selecciona un directorio:")
source_directory_label.grid(row=0, column=0, padx=10, pady=5)

# Botón para examinar directorio
source_directory_button = tk.Button(create_dir_frame_tab, text="Examinar", command=browse_source_directory)
source_directory_button.grid(row=0, column=2, padx=10, pady=5)

# Botón para crear directorio
create_directory_button = tk.Button(create_dir_frame_tab, text="Crear Directorio", command=crear_directorio)
create_directory_button.grid(row=1, column=1, padx=10, pady=5)

# Botón para eliminar directorio
delete_directory_button = tk.Button(create_dir_frame_tab, text="Eliminar Directorio", command=borrar_directorio)
delete_directory_button.grid(row=2, column=1, padx=10, pady=5)

# Cuadro de texto para mostrar el estado de la operación
status_directory_text = tk.Text(create_dir_frame_tab, width=60, height=3, state="disabled")
status_directory_text.grid(row=3, column=0, columnspan=3, padx=10, pady=5)

# Cuadro de texto para mostrar la ruta del directorio
directory_path_text = tk.Text(create_dir_frame_tab, width=60, height=3, state="disabled")
directory_path_text.grid(row=4, column=0, columnspan=3, padx=10, pady=5)




# Pestaña para mirar particiones
partitions_tab = ttk.Frame(organize_files_notebook)
organize_files_notebook.add(partitions_tab, text="Mirar Particiones")

# Cuadro de texto para mostrar resultados de particiones
result_textbox_particiones = tk.Text(partitions_tab, width=80, height=20, state="disabled", bg="white")
result_textbox_particiones.grid(row=0, column=0, padx=10, pady=5)

# Botón para mirar particiones
partitions_button = tk.Button(partitions_tab, text="Mirar Particiones", command=mirar_particiones)
partitions_button.grid(row=1, column=0, padx=10, pady=10)

# Estilo para encabezados
result_textbox_particiones.tag_configure("header", font=("Helvetica", 12, "bold"))







# Pestaña para obtener porcentaje de batería
battery_tab = ttk.Frame(organize_files_notebook)
organize_files_notebook.add(battery_tab, text="Porcentaje de Batería")

# Cuadro de texto para mostrar resultados de batería
result_textbox_bateria = tk.Text(battery_tab, width=80, height=20, state="disabled", bg="white")
result_textbox_bateria.grid(row=0, column=0, padx=10, pady=5)

# Botón para obtener porcentaje de batería
battery_button = tk.Button(battery_tab, text="Obtener Porcentaje de Batería", command=porcentaje_bateria)
battery_button.grid(row=1, column=0, padx=10, pady=10)


result_textbox_bateria.tag_configure("header", font=("Helvetica", 12, "bold"))

listar_tab = ttk.Frame(organize_files_notebook)
organize_files_notebook.add(listar_tab, text="Listar Contenido")

# Etiqueta y campo de entrada para seleccionar el directorio
directory_label = tk.Label(listar_tab, text="Directorio:")
directory_label.grid(row=0, column=0, padx=10, pady=5)

directory_entry = tk.Entry(listar_tab, width=50)
directory_entry.grid(row=0, column=1, padx=10, pady=5)

# Botón para abrir el explorador de archivos y seleccionar el directorio
browse_button = tk.Button(listar_tab, text="Examinar", command=browse_directory)
browse_button.grid(row=0, column=2, padx=10, pady=5)

list_directory_button = tk.Button(listar_tab, text="Listar Contenido del Directorio", command=lambda: list_directory_contents(directory_entry.get()))
list_directory_button.grid(row=1, column=1, padx=10, pady=5)


# Cuadro de texto para mostrar el contenido del directorio
result_textbox_dir = tk.Text(listar_tab, width=80, height=20, state="disabled")
result_textbox_dir.grid(row=2, column=0, columnspan=3, padx=10, pady=5, sticky="nsew")




rename_files_frame = ttk.Frame(organize_files_notebook)
organize_files_notebook.add(rename_files_frame, text="Renombrar Archivos")

rename_source_label = tk.Label(rename_files_frame, text="Directorio de Origen:")
rename_source_label.grid(row=0, column=0, padx=10, pady=5)

rename_source_entry = tk.Entry(rename_files_frame, width=50)
rename_source_entry.grid(row=1, column=0, padx=10, pady=5)

rename_source_button = tk.Button(rename_files_frame, text="Examinar", command=browse_directory_rename)
rename_source_button.grid(row=1, column=1, padx=10, pady=5)

single_file_var = tk.BooleanVar()
single_file_checkbutton = tk.Checkbutton(rename_files_frame, text="Renombrar solo un archivo", variable=single_file_var, command=toggle_single_file_entry)
single_file_checkbutton.grid(row=2, column=0, columnspan=2, padx=10, pady=5)

single_file_entry = tk.Entry(rename_files_frame, width=50, state=tk.DISABLED)
single_file_entry.grid(row=3, column=0, padx=10, pady=5)

browse_file_button = tk.Button(rename_files_frame, text="Examinar Archivo", command=browse_single_file, state=tk.DISABLED)
browse_file_button.grid(row=3, column=1, padx=10, pady=5)

rename_button = tk.Button(rename_files_frame, text="Renombrar", command=rename_files_gui)
rename_button.grid(row=4, column=0, columnspan=2, padx=10, pady=10)







########################################################################################################################################################################################################################
########################################################################################################################################################################################################################
##########################################################################  <--- Ejecutar Comando  ---> ############################################################################################################ 
########################################################################################################################################################################################################################
########################################################################################################################################################################################################################





# Crear y posicionar el LabelFrame para organizar los widgets
execute_command_frame = tk.LabelFrame(root, text="Ejecutar Comando")
execute_command_frame.grid(row=1, column=0, padx=10, pady=5, sticky="nsew")

# Configurar columnas y filas para que se expandan con el cambio de tamaño de la ventana
execute_command_frame.columnconfigure(0, weight=1)
execute_command_frame.columnconfigure(1, weight=1)
execute_command_frame.rowconfigure(3, weight=1)

# Crear y posicionar los widgets dentro del LabelFrame
command_label = tk.Label(execute_command_frame, text="Comando:")
command_label.grid(row=0, column=0, padx=10, pady=5, sticky="e")

command_entry = tk.Entry(execute_command_frame, width=50)
command_entry.grid(row=0, column=1, padx=10, pady=5, sticky="ew")

use_console_var = tk.IntVar()
console_checkbox = tk.Checkbutton(execute_command_frame, text="Ejecutar en Consola", variable=use_console_var)
console_checkbox.grid(row=1, column=1, padx=10, pady=5, sticky="w")

execute_button = tk.Button(execute_command_frame, text="Ejecutar Comando", command=execute_command)
execute_button.grid(row=2, column=1, padx=10, pady=5, sticky="ew")

# Crear el cuadro de texto para mostrar resultados dentro del frame
result_textbox_commando = tk.Text(execute_command_frame, width=110, height=20, state="disabled")
result_textbox_commando.grid(row=3, column=0, columnspan=2, padx=10, pady=5, sticky="nsew")








########################################################################################################################################################################################################################
########################################################################################################################################################################################################################
##########################################################################  <--- Rastrear Sitio Web Y Generar URL Amigable ---> ############################################################################################################ 
########################################################################################################################################################################################################################
########################################################################################################################################################################################################################



# Crear y posicionar el notebook para las pestañas dentro del LabelFrame
web_notebook = ttk.Notebook(root)
web_notebook.grid(row=0, column=1, padx=10, pady=5, sticky="nsew")

# Pestaña para el monitoreo de red
monitor_tab_ = ttk.Frame(web_notebook)
web_notebook.add(monitor_tab_, text="Rastrear Sitio Web")

domain_label = tk.Label(monitor_tab_, text="Nombre de Dominio:")
domain_label.grid(row=0, column=0, padx=10, pady=5)

domain_entry = tk.Entry(monitor_tab_, width=50)
domain_entry.grid(row=0, column=1, padx=10, pady=5)

show_button = tk.Button(monitor_tab_, text="Mostrar IP y Enlaces", command=show_ip_and_links)
show_button.grid(row=3, column=1)

ip_label = tk.Label(monitor_tab_, text="")
ip_label.grid(row=1, column=0, columnspan=3, padx=10, pady=5)

links_textbox = tk.Text(monitor_tab_, width=100, height=15, state="disabled")
links_textbox.grid(row=2, column=0, columnspan=3, padx=10, pady=5)


monitor_tab_ = ttk.Frame(web_notebook)
web_notebook.add(monitor_tab_, text="URL Amigables")

text_label = tk.Label(monitor_tab_, text="Texto:")
text_label.grid(row=0, column=0, padx=10, pady=5)

text_entry = tk.Entry(monitor_tab_, width=50)
text_entry.grid(row=0, column=1, padx=10, pady=5)

generate_button = tk.Button(monitor_tab_, text="Generar URL", command=generate_url)
generate_button.grid(row=1, column=0, columnspan=2, padx=10, pady=10)

url_label_dos = tk.Label(monitor_tab_, text="")
url_label_dos.grid(row=2, column=0, columnspan=2, padx=10, pady=5)




########################################################################################################################################################################################################################
########################################################################################################################################################################################################################
##########################################################################  <--- Monitoreo de Red  ---> ############################################################################################################ 
########################################################################################################################################################################################################################
########################################################################################################################################################################################################################





# Crear y posicionar el notebook para las pestañas dentro del LabelFrame
network_monitor_notebook = ttk.Notebook(root)
network_monitor_notebook.grid(row=1, column=1, padx=10, pady=5, sticky="nsew")

# Pestaña para el monitoreo de red
monitor_tab = ttk.Frame(network_monitor_notebook)
network_monitor_notebook.add(monitor_tab, text="Puertos / Procesos")

detect_ports_button = tk.Button(monitor_tab, text="Detectar Puertos", command=detectar_puertos_gui)
detect_ports_button.grid(row=0, column=0, padx=5, pady=5)


list_processes_button = tk.Button(monitor_tab, text="Listar Procesos", command=listar_procesos_activos_gui)
list_processes_button.grid(row=0, column=1, padx=5, pady=5)

terminate_process_frame = ttk.LabelFrame(monitor_tab, text="Terminar Proceso")
terminate_process_frame.grid(row=0, column=2, padx=5, pady=5)

pid_label = tk.Label(terminate_process_frame, text="PID del Proceso:")
pid_label.grid(row=0, column=0, padx=5, pady=5)

pid_entry = tk.Entry(terminate_process_frame, width=20)
pid_entry.grid(row=0, column=1, padx=5, pady=5)

terminate_button = tk.Button(terminate_process_frame, text="Terminar Proceso", command=terminar_proceso_gui)
terminate_button.grid(row=0, column=2, padx=5, pady=5)
termination_result_label = tk.Label(terminate_process_frame, text="")
# Crear un cuadro de texto para mostrar los resultados
result_textbox = tk.Text(monitor_tab, width=100, height=25, state="disabled")
result_textbox.grid(row=1, column=0, columnspan=3, padx=10, pady=5)


ping_frame = ttk.Frame(network_monitor_notebook)
network_monitor_notebook.add(ping_frame, text="Ping")

host_label = tk.Label(ping_frame, text="Host:")
host_label.grid(row=0, column=0, padx=10, pady=5)

host_entry = tk.Entry(ping_frame, width=50)
host_entry.grid(row=0, column=1, padx=10, pady=5)

ping_button = tk.Button(ping_frame, text="Hacer Ping", command=ping_host)
ping_button.grid(row=0, column=2, padx=10, pady=5)

result_box = tk.Text(ping_frame, width=100, height=25, state="disabled")
result_box.grid(row=1, column=0, columnspan=3, padx=10, pady=5)


nmap_frame = ttk.Frame(network_monitor_notebook)
network_monitor_notebook.add(nmap_frame, text="Nmap")


# Agregar un Entry para ingresar el comando de Nmap
nmap_command_entry = tk.Entry(nmap_frame, width=50)
nmap_command_entry.grid(padx=10, pady=10)

# Agregar un botón para ejecutar el comando de Nmap
execute_button = tk.Button(nmap_frame, text="Ejecutar comando Nmap", command=execute_nmap_command)
execute_button.grid(pady=10)

# Agregar un widget de texto para mostrar el resultado del comando de Nmap
nmap_result_text = tk.Text(nmap_frame, width=100, height=23, state="disabled")
nmap_result_text.grid(padx=10, pady=10)

http_traffic_tab = ttk.Frame(network_monitor_notebook)
network_monitor_notebook.add(http_traffic_tab, text="HTTP")

# Agregar widgets para ingresar la URL y mostrar resultados
url_label = tk.Label(http_traffic_tab, text="URL:")
url_label.grid(row=0, column=0, padx=10, pady=5)

url_entry = tk.Entry(http_traffic_tab, width=50)
url_entry.grid(row=0, column=1, padx=10, pady=5)

monitor_button = tk.Button(http_traffic_tab, text="HTML", command=monitor_http_traffic_gui)
monitor_button.grid(row=0, column=2, padx=10, pady=5)

result_text = tk.Text(http_traffic_tab, width=100, height=25, state="disabled")
result_text.grid(row=1, column=0, columnspan=3, padx=10, pady=5)


bandwidth_frame = ttk.Frame(network_monitor_notebook)
network_monitor_notebook.add(bandwidth_frame, text="Ancho de Banda")

# Agregar un botón para iniciar el monitoreo del ancho de banda
bandwidth_button = tk.Button(bandwidth_frame, text="Monitorear Ancho de Banda", command=monitor_bandwidth)
bandwidth_button.pack(padx=10, pady=10)

# Agregar un widget de texto para mostrar la información del ancho de banda
bandwidth_text = tk.Text(bandwidth_frame, width=80, height=20, state="disabled")
bandwidth_text.pack(padx=10, pady=10)

network = ttk.Frame(network_monitor_notebook)
network_monitor_notebook.add(network, text="Interfaces de Red")


# Crear un botón para obtener la información de las interfaces de red
interfaces_button = tk.Button(network, text="Obtener Info de Interfaces de Red", command=obtener_info_interfaces_red)
interfaces_button.grid(row=2, column=0, padx=5, pady=5)

# Crear un cuadro de texto para mostrar el resultado de la información de las interfaces de red
result_textbox_interfaces = tk.Text(network, width=100, height=25, state="disabled")
result_textbox_interfaces.grid(row=3, column=0, padx=10, pady=5)


# Crear un marco para la pestaña "Netstat"
netstat_tab = ttk.Frame(network_monitor_notebook)
network_monitor_notebook.add(netstat_tab, text="Netstat")

# Crear un marco para los widgets dentro de la pestaña "Netstat"
netstat_widgets_frame = ttk.Frame(netstat_tab)
netstat_widgets_frame.pack(pady=5)

# Cuadro de texto para mostrar el resultado de netstat
resultado_text = tk.Text(netstat_widgets_frame, width=100, height=20, state="disabled")
resultado_text.grid(row=3, column=0, columnspan=2, padx=5, pady=5)

# Etiqueta y opción para seleccionar
ttk.Label(netstat_widgets_frame, text="Selecciona la opción que quieres utilizar con el comando netstat:").grid(row=0, column=0, columnspan=2, pady=10)
opcion_netstat = ttk.Combobox(netstat_widgets_frame, values=[
    "Muestra todas las conexiones, tanto activas como inactivas.",
    "Muestra solo las conexiones TCP.",
    "Muestra solo las conexiones UDP.",
    "Muestra el nombre del programa que está utilizando cada puerto.",
    "Muestra la tabla de enrutamiento."
], width=60)
opcion_netstat.grid(row=1, column=0, columnspan=2, padx=5, pady=10)
opcion_netstat.current(0)

# Botón para ejecutar la opción seleccionada
ttk.Button(netstat_widgets_frame, text="Ejecutar", command=netstat_op).grid(row=2, column=0, columnspan=2, pady=5)



########################################################################################################################################################################################################################
########################################################################################################################################################################################################################
##########################################################################  <--- Ejecucion  ---> ############################################################################################################ 
########################################################################################################################################################################################################################
########################################################################################################################################################################################################################



# Ajustar el tamaño de las columnas y filas
root.columnconfigure(0, weight=1)
root.columnconfigure(1, weight=1)
root.columnconfigure(2, weight=1)
root.rowconfigure(0, weight=1)
root.rowconfigure(1, weight=1)
root.rowconfigure(2, weight=1)

# Ejecutar el bucle principal de la aplicación
root.mainloop()



########################################################################################################################################################################################################################
########################################################################################################################################################################################################################






