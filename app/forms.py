from django import forms
from .models import Meep, Profile, Comment, Report
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User


class ProfilePicForm(forms.ModelForm):
    profile_image = forms.ImageField(label=("Profile Picture"), required=False)
    profile_bio = forms.CharField(label=("Profile Bio"), widget=forms.Textarea(attrs={'class':'form-control', 'placeholder':'Profile Bio',  }), required=False)
    homepage_link = forms.CharField(label=("Homepage Link"), widget=forms.TextInput(attrs={'class':'form-control', 'placeholder':'Homepage Link', }), required=False)
    facebook_link = forms.CharField(label=("Facebook Link"), widget=forms.TextInput(attrs={'class':'form-control', 'placeholder':'Facebook Link', }), required=False)
    instagram_link = forms.CharField(label=("Instagram Link"), widget=forms.TextInput(attrs={'class':'form-control', 'placeholder':'Instagram Link',  }), required=False)
    linkedin_link = forms.CharField(label=("LinkedIn Link"), widget=forms.TextInput(attrs={'class':'form-control', 'placeholder':'LinkedIn Link', }), required=False)
    
    class Meta:
        model = Profile
        fields = ('profile_image', 'profile_bio', 'homepage_link', 'facebook_link', 'instagram_link', 'linkedin_link',)


class MeepForm(forms.ModelForm):
    body = forms.CharField(required=True, widget=forms.widgets.Textarea(
        attrs=
        {"placeholder": "Write what's on your mind",
         "class": "form-control",  }
    ),
    label="",
    )
    image = forms.ImageField(required=False,widget=forms.widgets.FileInput(
        attrs=
        {"placeholder": "Choose Image",
         "class": "form-control", }
    ),
    label="",
    ) 
    
    class Meta:
        model = Meep
        fields = ('body', 'image')
        exclude = ("user", "likes")

class CommentForm(forms.ModelForm):
    class Meta:
        model = Comment
        fields = ['body'] 

class SignUpForm(UserCreationForm):
   
    email = forms.EmailField(label=("Email"), widget=forms.TextInput(attrs={'class':'form-control', }))
    first_name = forms.CharField(label=("First Name"), max_length=100, widget=forms.TextInput(attrs={'class':'form-control',}))
    last_name = forms.CharField(label=("Last Name"), max_length=100, widget=forms.TextInput(attrs={'class':'form-control', }))
    
    class Meta:
        model = User
        fields = ('username', 'first_name', 'last_name', 'email', 'password1', 'password2')

    def __init__(self, *args, **kwargs):
        super(SignUpForm, self).__init__(*args, **kwargs)
        
        self.fields['username'].widget.attrs['class'] = 'form-control'
        self.fields['username'].label = ''
        self.fields['username'].help_text = '<span class="form-text text-primary "><small>Required. 150 characters or fewer. Letters, digits and @/./+/-/_ only.</small></span>'
        
        self.fields['password1'].widget.attrs['class'] = 'form-control'
        self.fields['password1'].label = 'Password'
        self.fields['password1'].help_text = '<ul class="form-text text-primary"><li>Your password can’t be too similar to your other personal information.</li><li>Your password must contain at least 8 characters.</li><li>Your password can’t be a commonly used password.</li><li>Your password can’t be entirely numeric.</li></ul>'
        
        self.fields['password2'].widget.attrs['class'] = 'form-control'
        self.fields['password2'].label = 'Confirm Password'
        self.fields['password2'].help_text = '<span class="form-text text-primary"><small>Enter the same password as before, for verification.</small></span>'


class AnonymousReportForm(forms.ModelForm):
    class Meta:
        model = Report
        fields = ['meep', 'report_type', 'description']
