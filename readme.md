This was built with my own use case in mind.  It's intended that you make your own branch of this and update accordingly.  This is a template that leaves placeholders for things like azure automation account private link account id's, or devops organisation names.  They do not include my tenant.  This readme will keep track of custom changes you need to make (or remove from the build script altogether if you have no use for them)


change URLs to reflect your azure devops organisation name in Inputs\domains\Microsoft_Azure_Devops_Custom_URLs.txt

change azure automation to suit your region
if you are using privatelink, set your account id's in the private link file