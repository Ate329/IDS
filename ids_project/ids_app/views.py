import logging
from django.shortcuts import render, redirect
from django.views.decorators.csrf import ensure_csrf_cookie
from django.views.decorators.http import require_http_methods
from django.utils import timezone
from datetime import timedelta
from django.db import models
from .models import IDSStatus, TrafficData
from .IDS import IntrusionDetectionSystem
import threading
from collections import Counter
import traceback
from django.utils import timezone
from datetime import timedelta
import os
from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
import csv
from django.db.models import Sum
from django.utils import timezone
from datetime import timedelta
from django.db.models.functions import TruncHour
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from .models import EmailSettings
from .models import IDSSettings
import json


logger = logging.getLogger(__name__)

# Absolute paths for important files
PROJECT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
MODELS_DIR = os.path.join(PROJECT_DIR, "models")  # Models directory
TRAFFIC_DATA_CSV = os.path.join(PROJECT_DIR, "traffic_data.csv")  # Traffic data CSV
SCALER_FILE = os.path.join(PROJECT_DIR, "scaler.joblib")  # Scaler file
IDS_LOG = os.path.join(PROJECT_DIR, "ids_log.txt")  # Log file

ids_instance = None
ids_thread = None


@ensure_csrf_cookie
def dashboard(request):
    return render(request, 'ids_app/dashboard.html')


@ensure_csrf_cookie
def logs(request):
    return render(request, 'ids_app/logs.html')


@ensure_csrf_cookie
def traffic(request):
    return render(request, 'ids_app/traffic.html')


@ensure_csrf_cookie
def settings(request):
    return render(request, 'ids_app/settings.html')


def get_logs(request):
    if not os.path.exists(IDS_LOG):
        open(IDS_LOG, 'a').close()
    try:
        with open(IDS_LOG, 'r') as log_file:
            logs = log_file.read()
        return HttpResponse(logs, content_type='text/plain')
    except Exception as e:
        logger.error("Error reading logs: %s", traceback.format_exc())
        return JsonResponse({'error': 'An internal error has occurred.'}, status=500)


def get_traffic_data_csv(request):
    if not os.path.exists(TRAFFIC_DATA_CSV):
        open(TRAFFIC_DATA_CSV, 'a').close()
    try:
        with open(TRAFFIC_DATA_CSV, 'r') as csv_file:
            csv_content = csv_file.read()
        return HttpResponse(csv_content, content_type='text/csv')
    except Exception as e:
        logger.error("Error reading traffic data CSV: %s", traceback.format_exc())
        return JsonResponse({'error': 'An internal error has occurred.'}, status=500)


@csrf_exempt
@require_http_methods(["POST"])
def clean_database(request):
    try:
        TrafficData.objects.all().delete()
        IDSStatus.objects.all().delete()
        return JsonResponse({'success': True, 'message': 'Database cleaned successfully'})
    except Exception as e:
        logger.error(f"Error cleaning database: {str(e)}")
        return JsonResponse({'success': False, 'error': 'Failed to clean database'}, status=500)


@csrf_exempt
@require_http_methods(["POST"])
def clean_log_file(request):
    try:
        open('ids_log.txt', 'w').close()
        return JsonResponse({'success': True, 'message': 'Log file cleaned successfully'})
    except Exception as e:
        logger.error(f"Error cleaning log file: {str(e)}")
        return JsonResponse({'success': False, 'error': 'Failed to clean log file'}, status=500)


@csrf_exempt
@require_http_methods(["POST"])
def clean_traffic_data(request):
    try:
        open('traffic_data.csv', 'w').close()
        return JsonResponse({'success': True, 'message': 'Traffic data file cleaned successfully'})
    except Exception as e:
        logger.error(f"Error cleaning traffic data file: {str(e)}")
        return JsonResponse({'success': False, 'error': 'Failed to clean traffic data file'}, status=500)


@csrf_exempt
@require_http_methods(["POST"])
def clean_scaler(request):
    try:
        if os.path.exists(SCALER_FILE):
            os.remove(SCALER_FILE)
            return JsonResponse({'success': True, 'message': 'Scaler file removed successfully'})
        else:
            return JsonResponse({'success': True, 'message': 'Scaler file does not exist'})
    except Exception as e:
        logger.error(f"Error removing scaler file: {str(e)}")
        return JsonResponse({'success': False, 'error': 'Failed to remove scaler file'}, status=500)


def get_ids_status(request):
    status, created = IDSStatus.objects.get_or_create(
        pk=1, defaults={'is_active': False})
    logger.debug(f"IDS status requested: {status.is_active}")
    return JsonResponse({'is_active': status.is_active})


def get_available_interfaces(request):
    interfaces = IntrusionDetectionSystem.get_available_interfaces()
    return JsonResponse({'interfaces': interfaces})


@require_http_methods(["POST"])
def set_interface(request):
    interface = request.POST.get('interface')
    if not interface:
        return JsonResponse({'error': 'No interface provided'}, status=400)

    global ids_instance
    if ids_instance:
        ids_instance.set_interface(interface)
        return JsonResponse({'success': True, 'message': f'Interface set to {interface}'})
    else:
        return JsonResponse({'error': 'IDS is not initialized'}, status=400)


def get_current_interface(request):
    global ids_instance
    if ids_instance:
        return JsonResponse({'interface': ids_instance.interface})
    else:
        return JsonResponse({'error': 'IDS is not initialized'}, status=400)

def get_traffic_data(request):
    global ids_instance
    if ids_instance and ids_instance.is_running():
        with ids_instance.buffer_lock:  # Use the same lock as in IDS class
            total_packets = ids_instance.packet_count
            normal_packets = ids_instance.normal_count
            anomaly_packets = ids_instance.anomaly_count

        # Ensure total_packets is at least the sum of normal and anomaly packets
        total_packets = max(total_packets, normal_packets + anomaly_packets)

        # Get the latest connection
        latest_conn_key = next(
            reversed(ids_instance.feature_extractor.connections.keys()), None)
        latest_conn = ids_instance.feature_extractor.connections.get(
            latest_conn_key)

        if latest_conn and latest_conn_key:
            protocol_type = ids_instance.feature_extractor.PROTOCOL_TYPES.get(
                latest_conn_key[4], 'ARP')
            flag = latest_conn.flags[-1] if latest_conn.flags else ''
        else:
            protocol_type = ''
            flag = ''
    else:
        # If IDS is not running, return the last known values from the database
        last_data = TrafficData.objects.last()
        if last_data:
            total_packets = last_data.total_packets
            normal_packets = last_data.normal_packets
            anomaly_packets = last_data.anomaly_packets
            protocol_type = last_data.protocol_type
            flag = last_data.flag
        else:
            return JsonResponse({'error': 'No data available'})

    # Ensure total_packets is at least the sum of normal and anomaly packets
    total_packets = max(total_packets, normal_packets + anomaly_packets)

    return JsonResponse({
        'total_packets': total_packets,
        'normal_packets': normal_packets,
        'anomaly_packets': anomaly_packets,
        'protocol_type': protocol_type,
        'flag': flag,
    })


def get_historical_data(request):
    end_time = timezone.now().replace(minute=0, second=0, microsecond=0)
    start_time = end_time - timedelta(hours=24)

    # Group data by hour and get the sum of packets
    data = TrafficData.objects.filter(timestamp__range=(start_time, end_time)) \
        .annotate(hour=TruncHour('timestamp')) \
        .values('hour') \
        .annotate(
            total_packets=Sum('total_packets'),
            normal_packets=Sum('normal_packets'),
            anomaly_packets=Sum('anomaly_packets')
        ) \
        .order_by('hour')

    # Create a dictionary with all hours initialized to 0
    all_hours = {start_time + timedelta(hours=i): {
        'total_packets': 0,
        'normal_packets': 0,
        'anomaly_packets': 0
    } for i in range(25)}  # 25 to include the current hour

    # Update the dictionary with actual data
    for entry in data:
        all_hours[entry['hour']] = {
            'total_packets': entry['total_packets'],
            'normal_packets': entry['normal_packets'],
            'anomaly_packets': entry['anomaly_packets']
        }

    # Ensure data consistency
    for hour_data in all_hours.values():
        hour_data['total_packets'] = max(hour_data['total_packets'], 
                                         hour_data['normal_packets'] + hour_data['anomaly_packets'])

    # Format data for the response
    formatted_data = {
        'timestamps': [hour.isoformat() for hour in all_hours.keys()],
        'total_packets': [data['total_packets'] for data in all_hours.values()],
        'normal_packets': [data['normal_packets'] for data in all_hours.values()],
        'anomaly_packets': [data['anomaly_packets'] for data in all_hours.values()],
    }

    # Get protocol and flag distribution (last 24 hours)
    protocol_data = TrafficData.objects.filter(timestamp__range=(start_time, end_time)) \
        .values('protocol_type') \
        .annotate(count=Sum('total_packets')) \
        .order_by('-count')[:5]

    flag_data = TrafficData.objects.filter(timestamp__range=(start_time, end_time)) \
        .values('flag') \
        .annotate(count=Sum('total_packets')) \
        .order_by('-count')[:5]

    formatted_data['protocol_types'] = {entry['protocol_type']: entry['count'] for entry in protocol_data}
    formatted_data['flags'] = {entry['flag']: entry['count'] for entry in flag_data}

    return JsonResponse(formatted_data)


def get_csv_data(request):
    protocol_counter = Counter()
    flag_counter = Counter()
    total_packets = 0
    normal_packets = 0
    anomaly_packets = 0

    try:
        # Ensure the file exists
        if not os.path.exists('traffic_data.csv'):
            open('traffic_data.csv', 'w').close() 
            
        with open('traffic_data.csv', 'r') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                total_packets += 1
                if row['class'] == 'normal':
                    normal_packets += 1
                else:
                    anomaly_packets += 1
                protocol_counter[row['protocol_type']] += 1
                flag_counter[row['flag']] += 1

        return JsonResponse({
            'total_packets': total_packets,
            'normal_packets': normal_packets,
            'anomaly_packets': anomaly_packets,
            'protocol_types': dict(protocol_counter.most_common(5)),
            'flags': dict(flag_counter.most_common(5))
        })
    except Exception as e:
        logger.error("An error occurred while processing the CSV data: %s", str(e))
        return JsonResponse({'error': 'An internal error has occurred!'}, status=500)


@require_http_methods(["GET"])
def get_email_settings(request):
    settings, created = EmailSettings.objects.get_or_create(pk=1)
    return JsonResponse({
        'email_sender': settings.email_sender,
        'email_recipient': settings.email_recipient,
        'smtp_server': settings.smtp_server,
        'smtp_port': settings.smtp_port,
    })

@require_http_methods(["POST"])
def update_email_settings(request):
    email_sender = request.POST.get('email_sender')
    email_password = request.POST.get('email_password')
    email_recipient = request.POST.get('email_recipient')
    smtp_server = request.POST.get('smtp_server')
    smtp_port = request.POST.get('smtp_port')

    settings, created = EmailSettings.objects.get_or_create(pk=1)
    settings.email_sender = email_sender
    if email_password:  # Only update password if provided
        settings.email_password = email_password
    settings.email_recipient = email_recipient
    settings.smtp_server = smtp_server
    settings.smtp_port = int(smtp_port)
    settings.save()

    return JsonResponse({'success': True, 'message': 'Email settings updated successfully'})


@require_http_methods(["GET"])
def get_ids_settings(request):
    settings = IDSSettings.get_settings()
    return JsonResponse({
        'detect_internal': settings.detect_internal,
    })


@require_http_methods(["POST"])
def update_ids_settings(request):
    detect_internal = request.POST.get('detect_internal') == 'true'
    settings = IDSSettings.get_settings()
    settings.detect_internal = detect_internal
    settings.save()

    global ids_instance
    if ids_instance:
        ids_instance.feature_extractor.detect_internal = detect_internal

    return JsonResponse({'success': True, 'message': 'IDS settings updated successfully'})


@require_http_methods(["POST"])
def toggle_ids(request):
    global ids_instance, ids_thread
    status, created = IDSStatus.objects.get_or_create(
        pk=1, defaults={'is_active': False})

    try:
        if not status.is_active:
            logger.info("Activating IDS")
            if not ids_instance:
                settings = IDSSettings.get_settings()
                ids_instance = IntrusionDetectionSystem(
                    os.path.join(MODELS_DIR, "NSL-KDD-RF-model.joblib"),
                    os.path.join(MODELS_DIR, "feature_names.pkl"),
                    detect_internal=settings.detect_internal
                )
            if not ids_thread or not ids_thread.is_alive():
                ids_thread = threading.Thread(
                    target=ids_instance.start_detection)
                ids_thread.start()
            status.is_active = True
        else:
            logger.info("Deactivating IDS")
            if ids_instance:
                ids_instance.stop_detection()
            status.is_active = False

        status.save()
        logger.info(f"IDS status toggled to: {status.is_active}")
        return JsonResponse({'is_active': status.is_active})
    except Exception as e:
        error_message = f"Error toggling IDS: {str(e)}"
        logger.error(f"{error_message}\n{traceback.format_exc()}")
        return JsonResponse({'error': "An internal error has occurred. Please try again later."}, status=500)