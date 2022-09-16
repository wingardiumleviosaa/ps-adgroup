Start-Sleep -Seconds 1
# Create Group
try {
	New-ADGroup -Server 'hqnhudc1.whq.wistron' -Name 'AZRSRE-Default-Role' -SamAccountName 'AZRSRE-Default-Role' -GroupCategory Security -GroupScope Universal -DisplayName 'AZRTILLO-Default-Role' -Path 'OU=CCOE,OU=Security_Group,OU=Group_Object,DC=whq,DC=wistron' -Description 'CCOE' -ErrorAction Stop
	echo 'create AD Group'
	Start-Sleep -Seconds 3
	Import-Module ActiveDirectory
	New-PSDrive -Name ad -PSProvider ActiveDirectory -Root 'OU=CCOE,OU=Security_Group,OU=Group_Object,DC=whq,DC=wistron' -server 'hqnhudc1.whq.wistron'
	set-location ad:\
	Start-Sleep -Seconds 5
	do{
		$Failed = $false
		Try{
			$acl = Get-Acl -path 'Microsoft.ActiveDirectory.Management.dll\ActiveDirectory:://RootDSE/CN=AZRSRE-Default-Role,OU=CCOE,OU=Security_Group,OU=Group_Object,DC=whq,DC=wistron' -ErrorAction Stop
			echo 'group successfully create!'
			$guid =[guid]'bf9679c0-0de6-11d0-a285-00aa003049e2'
			$user = New-Object System.Security.Principal.NTAccount('whq\10612703')
			$sid =$user.translate([System.Security.Principal.SecurityIdentifier])

			$ctrl =[System.Security.AccessControl.AccessControlType]::Allow
			$rights =[System.DirectoryServices.ActiveDirectoryRights]::WriteProperty -bor[System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight
			$intype =[System.DirectoryServices.ActiveDirectorySecurityInheritance]::None

			## set the ManagedBy property
			# base on user's AD domian
			$UserDN=Get-ADUser -Server 'hqnhudc1.whq.wistron' -Identity '10612703'

			$group =[adsi]'LDAP://hqnhudc1.whq.wistron:389/CN=AZRSRE-Default-Role,OU=CCOE,OU=Security_Group,OU=Group_Object,DC=whq,DC=wistron'
			$group.put("ManagedBy",$UserDN.DistinguishedName)
			$group.setinfo()
			$rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($sid,$rights,$ctrl,$guid)
			$acl.AddAccessRule($rule)
			Set-Acl -acl $acl -path 'Microsoft.ActiveDirectory.Management.dll\ActiveDirectory:://RootDSE/CN=AZRSRE-Default-Role,OU=CCOE,OU=Security_Group,OU=Group_Object,DC=whq,DC=wistron'
			$GroupDN=Get-ADGroup -Server 'hqnhudc1.whq.wistron' -Identity 'CN=AZRSRE-Default-Role,OU=CCOE,OU=Security_Group,OU=Group_Object,DC=whq,DC=wistron'
			Add-ADGroupMember -Identity $GroupDN -Members $UserDN -Server 'hqnhudc1.whq.wistron'
			echo 'set AD group ACL Process done'
	} catch { 
			$Failed = $true
			echo 'AD group have not sync yet. Next attempt in 10 seconds'
			Start-sleep -Seconds 10
		}
	} while ($Failed)

	echo 'Finish creating ad group shell'

	$Failed = $true
	do{
		$azgroup = az ad group list --display-name AZRSRE-Default-Role
		if ($azgroup.count -eq 1){
			$Failed = $true
			echo 'AD group have not sync yet. Next attempt in 60 seconds'
			Start-sleep -Seconds 60
		} else { 
			$Failed = $false
			echo 'group is synced to Azure AD'
		}
	} while ($Failed)
	
}catch{
	echo 'ad group exist!'
}
