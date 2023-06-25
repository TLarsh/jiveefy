# from django.shortcuts import render

# # Create your views here.

# from django.shortcuts import render
# import stripe
# from django.http import Http404
from django.conf import settings
# from django.contrib.auth import get_user_model
# User = get_user_model()

# from rest_framework.response import Response
# from rest_framework.authentication import TokenAuthentication
# from rest_framework.decorators import api_view, authentication_classes, permission_classes
# from rest_framework.views import APIView
# from rest_framework import status, authentication, permissions

# 
#


import stripe
from rest_framework.views import APIView
from rest_framework.response import Response

class StripePaymentView(APIView):
    def post(self, request):
        data = self.request.data
        # Retrieve the required data from the request, e.g., amount, currency, and payment method
        amount = request.data.get('amount')
        currency = request.data.get('currency')
        payment_method = request.data.get('payment_method')

        # Set up Stripe API key
        stripe.api_key = settings.STRIPE_SECRET_KEY

        try:
            # Create a payment intent
            intent = stripe.PaymentIntent.create(
                amount=amount,
                currency=currency,
                payment_method=payment_method,
                confirm=True,
            )
            
            # If the payment is successful, return a response
            if intent.status == 'succeeded':
                return Response({'message': 'Payment successful'})
            else:
                return Response({'message': 'Payment failed'})

        except stripe.error.CardError as e:
            # Handle specific card errors
            return Response({'message': str(e)})

        except stripe.error.StripeError as e:
            # Handle generic Stripe errors
            return Response({'message': str(e)})


