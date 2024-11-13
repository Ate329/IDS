from django.urls import path
from django.views.decorators.csrf import ensure_csrf_cookie
from . import views

urlpatterns = [
    path('', ensure_csrf_cookie(views.dashboard), name='dashboard'),
    path('logs/', ensure_csrf_cookie(views.logs), name='logs'),
    path('traffic/', ensure_csrf_cookie(views.traffic), name='traffic'),
    path('settings/', ensure_csrf_cookie(views.settings), name='settings'),
    path('api/ids-status/', views.get_ids_status, name='get_ids_status'),
    path('api/toggle-ids/', views.toggle_ids, name='toggle_ids'),
    path('api/traffic-data/', views.get_traffic_data, name='get_traffic_data'),
    path('api/historical-data/', views.get_historical_data, name='get_historical_data'),
    path('api/get-logs/', views.get_logs, name='get_logs'),
    path('api/get-traffic-data-csv/', views.get_traffic_data_csv, name='get_traffic_data_csv'),
    path('api/clean-database/', views.clean_database, name='clean_database'),
    path('api/clean-log-file/', views.clean_log_file, name='clean_log_file'),
    path('api/clean-traffic-data/', views.clean_traffic_data, name='clean_traffic_data'),
    path('api/clean-scaler/', views.clean_scaler, name='clean_scaler'),
    path('api/get-csv-data/', views.get_csv_data, name='get_csv_data'),
    path('api/get-available-interfaces/', views.get_available_interfaces, name='get_available_interfaces'),
    path('api/set-interface/', views.set_interface, name='set_interface'),
    path('api/get-current-interface/', views.get_current_interface, name='get_current_interface'),
    path('api/get-email-settings/', views.get_email_settings, name='get_email_settings'),
    path('api/update-email-settings/', views.update_email_settings, name='update_email_settings')
]